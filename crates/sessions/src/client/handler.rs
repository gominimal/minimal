//! Client-side handler for the daemon's [`ContributionResponse`].
//!
//! Gates each pending var and patch against the user's policy and
//! emits a [`ContributionVerdict`] to ship back via `SubmitVerdict`.
//! Vars are gated first: any that get approved join the loadout's
//! gated vars in the expansion context used to resolve patch source
//! patterns in the same call, so a patch declared with
//! `~/${PROJECT_ROOT}` can reference a `PROJECT_ROOT` approved
//! moments earlier in the same response.
//!
//! Lifecycle hooks are gated last, against the hooks policy, by the
//! project root that declared them: a hook is arbitrary code, so a
//! project must be allow-listed before any of its hooks run. Hooks are
//! decided per project rather than per script — a project's hooks are
//! approved as a set — so the prompt fires once per project no matter
//! how many scripts it declares.
//!
//! Per-domain verdicts are correlated by `id`, not slice position:
//! auto-decided items come out in input order but hook-routed items
//! land at the end.

use crate::core::compose::{
    ComposeError, ComposeOptions, HookDomain, PendingPatchFile, PendingVar, SessionVar,
    expand_patch_sources,
};
use crate::core::decision::{CheckOutcome, Decision, ItemDecision};
use crate::core::enumerate::enumerate_patch_files;
use crate::core::hooks::{PolicyHooks, Unapproved};
use crate::core::policy::{
    ExpandedPatchesPolicy, HooksPolicy, PatchesPolicy, UserPolicy, VarsPolicy,
};
use crate::core::primitives::{Patch, PatchDest};
use crate::core::source::{Provenanced, ProvenancedPatch, Source};
use crate::wire::policy::{WireHookVerdict, WirePatchVerdict, WireVarVerdict};
use crate::wire::primitives::{WirePendingHook, WirePendingPatch, WirePendingVar};
use crate::wire::request::{ContributionResponse, ContributionVerdict};

/// Gate the daemon's pending items against `policy`, prompting via
/// `hooks` for anything the policy can't auto-decide, and emit a
/// [`ContributionVerdict`] to ship back to the daemon.
///
/// `gated_vars` is the client's already-gated var set from the
/// loadout phase; pending patch sources may reference both those
/// and any vars approved in this response.
///
/// # Errors
///
/// See [`ComposeError`]. On [`ComposeError::Aborted`] (a hook
/// returned [`HookResult::Abort`]) the caller should skip
/// `SubmitVerdict` and send `AbortSession` instead so the daemon
/// releases its pending stash entry.
///
/// [`HookResult::Abort`]: crate::core::hooks::HookResult::Abort
pub fn handle_response(
    response: ContributionResponse,
    gated_vars: &[SessionVar],
    policy: UserPolicy,
    hooks: &dyn PolicyHooks,
    options: ComposeOptions,
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<(ContributionVerdict, UserPolicy), ComposeError> {
    let session_id = response.session_id;
    let (vars_policy, patches_policy, hooks_policy) = policy.into_parts();

    let (var_out, vars_policy) = gate_pending_vars(response.vars, vars_policy, hooks, env)?;

    let combined_vars: Vec<SessionVar> =
        gated_vars.iter().cloned().chain(var_out.approved).collect();

    let (patch_verdicts, patches_policy) = gate_pending_patches(
        response.patches,
        patches_policy,
        hooks,
        options,
        &combined_vars,
        env,
    )?;

    // Hooks gate last so its policy patterns can expand against the
    // same resolved var set the patch gate used.
    let (hook_verdicts, hooks_policy) = gate_pending_hooks(
        response.lifecycle_hooks,
        hooks_policy,
        hooks,
        &combined_vars,
        env,
    )?;

    let final_policy = UserPolicy::empty()
        .with_vars(vars_policy)
        .with_patches(patches_policy)
        .with_hooks(hooks_policy);

    Ok((
        ContributionVerdict {
            session_id,
            vars: var_out.verdicts,
            patches: patch_verdicts,
            lifecycle_hooks: hook_verdicts,
        },
        final_policy,
    ))
}

// =====================================================================
// Lifecycle hooks
// =====================================================================

/// One project whose hooks still need a decision: the root path the
/// prompt shows, the original [`Source`] (kept rather than rebuilt from
/// the path, so a re-check after the prompt matches on exactly what the
/// policy saw the first time), and the ids waiting on that decision.
type UndecidedProject = (
    camino::Utf8PathBuf,
    Source,
    Vec<crate::wire::primitives::PendingId>,
);

/// Gate the daemon's pending lifecycle hooks against the hooks policy.
///
/// Decisions are made **per project**, not per hook: a project's hooks
/// are approved or refused as a set, so a project declaring five hooks
/// prompts once rather than five times, and can't end up half-approved.
/// Every hook from one project therefore receives that project's single
/// decision.
fn gate_pending_hooks(
    pending: Vec<WirePendingHook>,
    policy: HooksPolicy,
    hooks: &dyn PolicyHooks,
    combined_vars: &[SessionVar],
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<(Vec<WireHookVerdict>, HooksPolicy), ComposeError> {
    if pending.is_empty() {
        return Ok((Vec::new(), policy));
    }
    let home_fallback = env("HOME").ok();
    let expanded = policy.expand_with(combined_vars, home_fallback.as_deref())?;

    // Pass 1: classify each hook. `Provenanced` is what the policy
    // reads, so a lightweight (id, source) pair stands in for the hook
    // itself here — the daemon holds the hook and only needs a verdict.
    let mut verdicts: Vec<WireHookVerdict> = Vec::with_capacity(pending.len());
    // Distinct projects still needing a decision, in first-seen order.
    let mut unapproved: Vec<UndecidedProject> = Vec::new();
    for p in pending {
        let source: Source = p.source.into();
        match expanded.check(HookRef {
            id: p.id,
            source: source.clone(),
        }) {
            CheckOutcome::Decided(Decision::Allowed(h)) => {
                verdicts.push(WireHookVerdict::Approved { id: h.id });
            }
            CheckOutcome::Decided(Decision::Denied(h)) => {
                verdicts.push(WireHookVerdict::Denied { id: h.id });
            }
            CheckOutcome::Decided(Decision::Ignored) => {
                verdicts.push(WireHookVerdict::Ignored { id: p.id });
            }
            CheckOutcome::NeedsApproval(h) => {
                // Only `Source::Project` reaches here — the other two
                // variants are always decided — so the path is present.
                let root = match &h.source {
                    Source::Project { path } => path.as_utf8_path().to_owned(),
                    other => {
                        return Err(ComposeError::InvalidWireItem {
                            what: "lifecycle hook needing approval from a non-project source",
                            context: format!("{other:?}"),
                        });
                    }
                };
                match unapproved.iter_mut().find(|(p, _, _)| *p == root) {
                    Some((_, _, ids)) => ids.push(h.id),
                    None => unapproved.push((root, h.source, vec![h.id])),
                }
            }
        }
    }
    if unapproved.is_empty() {
        return Ok((verdicts, policy));
    }

    // Pass 2: prompt once per project.
    let view: Vec<Unapproved<'_, camino::Utf8Path>> = unapproved
        .iter()
        .map(|(root, source, _)| Unapproved {
            item: root.as_path(),
            source,
        })
        .collect();
    let (decisions, policy) = crate::core::compose::prompt_hook_hook(hooks, policy, &view)?;

    // Pass 3: apply one decision to every hook from that project.
    let expanded = policy.expand_with(combined_vars, home_fallback.as_deref())?;
    for ((root, source, ids), decision) in unapproved.into_iter().zip(decisions) {
        for id in ids {
            let verdict = match decision {
                ItemDecision::AllowOnce => WireHookVerdict::Approved { id },
                ItemDecision::IgnoreOnce => WireHookVerdict::Ignored { id },
                ItemDecision::UseRule => match expanded.check(HookRef {
                    id,
                    source: source.clone(),
                }) {
                    CheckOutcome::Decided(Decision::Allowed(h)) => {
                        WireHookVerdict::Approved { id: h.id }
                    }
                    CheckOutcome::Decided(Decision::Denied(h)) => {
                        WireHookVerdict::Denied { id: h.id }
                    }
                    CheckOutcome::Decided(Decision::Ignored) => WireHookVerdict::Ignored { id },
                    CheckOutcome::NeedsApproval(_) => {
                        return Err(ComposeError::use_rule_undecided(
                            HookDomain::Hook,
                            format!("lifecycle hooks from project `{root}`"),
                        ));
                    }
                },
            };
            verdicts.push(verdict);
        }
    }
    Ok((verdicts, policy))
}

/// The minimum a hook needs to face the policy: its correlation id and
/// the source that declared it. The hook body stays on the daemon, so
/// the client never has to ship one back — only a decision.
#[derive(Clone, Debug)]
struct HookRef {
    id: crate::wire::primitives::PendingId,
    source: Source,
}

impl Provenanced for HookRef {
    fn source(&self) -> &Source {
        &self.source
    }
}

// =====================================================================
// Vars
// =====================================================================

/// Two-output result of processing a single pending var: the wire
/// verdict the daemon receives, and an optional [`SessionVar`] to
/// chain into patch expansion (only present when the decision was
/// `Allowed`).
struct VarOutcome {
    verdict: WireVarVerdict,
    approval: Option<SessionVar>,
}

/// Output of [`gate_pending_vars`]: the wire-form verdicts and the
/// approved vars to feed into patch expansion.
struct VarGateOutput {
    verdicts: Vec<WireVarVerdict>,
    approved: Vec<SessionVar>,
}

impl VarGateOutput {
    fn with_capacity(n: usize) -> Self {
        Self {
            verdicts: Vec::with_capacity(n),
            approved: Vec::new(),
        }
    }

    fn push(&mut self, outcome: VarOutcome) {
        if let Some(sv) = outcome.approval {
            self.approved.push(sv);
        }
        self.verdicts.push(outcome.verdict);
    }
}

fn gate_pending_vars(
    pending: Vec<WirePendingVar>,
    policy: VarsPolicy,
    hooks: &dyn PolicyHooks,
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<(VarGateOutput, VarsPolicy), ComposeError> {
    // Resolve every wire item to its domain form. Fails fast on the
    // first env-lookup miss for an `Inherit` spec.
    let pending: Vec<PendingVar> = pending
        .into_iter()
        .map(|w| PendingVar::from_wire(w, env))
        .collect::<Result<_, _>>()?;

    // Pass 1: classify. Items the policy can auto-decide flow into
    // `out`; items that need approval queue up for the hook.
    let (mut out, unapproved) = partition_var_classifications(
        pending.len(),
        pending.into_iter().map(|p| classify_var(&policy, p)),
    );
    if unapproved.is_empty() {
        return Ok((out, policy));
    }

    // Pass 2: prompt.
    let view: Vec<Unapproved<'_, str>> = unapproved
        .iter()
        .map(|p| Unapproved {
            item: p.name(),
            source: p.provenanced().source(),
        })
        .collect();
    let (decisions, policy) = crate::core::compose::prompt_var_hook(hooks, policy, &view)?;

    // Pass 3: apply the hook's decisions. UseRule re-routes back
    // through the classifier, which can't legally re-produce
    // `Pending` (the hook is the last word).
    for (p, d) in unapproved.into_iter().zip(decisions) {
        out.push(apply_var_decision(&policy, p, d)?);
    }
    Ok((out, policy))
}

/// Drain `classifications` into the finished `VarGateOutput` and a
/// queue of items that still need a hook decision.
fn partition_var_classifications(
    capacity: usize,
    classifications: impl IntoIterator<Item = VarClassification>,
) -> (VarGateOutput, Vec<PendingVar>) {
    let mut out = VarGateOutput::with_capacity(capacity);
    let mut unapproved = Vec::new();
    for c in classifications {
        match c {
            VarClassification::Decided(outcome) => out.push(outcome),
            VarClassification::Pending(p) => unapproved.push(p),
        }
    }
    (out, unapproved)
}

/// Apply a hook's `ItemDecision` to a single pending var. `AllowOnce`
/// produces an outcome directly; `UseRule` routes back through the
/// classifier and treats a still-undecidable result as a hook
/// contract violation.
fn apply_var_decision(
    policy: &VarsPolicy,
    pending: PendingVar,
    decision: ItemDecision,
) -> Result<VarOutcome, ComposeError> {
    match decision {
        ItemDecision::AllowOnce => {
            let approval = SessionVar::from_provenanced(pending.provenanced().clone());
            Ok(VarOutcome {
                verdict: pending.into_approved_verdict(),
                approval: Some(approval),
            })
        }
        // `IgnoreOnce`: silent drop for this activation. Same wire
        // shape as a policy `ignore` verdict (no approval, `Ignored`
        // verdict correlating back to the pending id), so the daemon
        // treats it identically.
        ItemDecision::IgnoreOnce => {
            let name = pending.name().to_owned();
            let (id, _pv) = pending.into_parts();
            Ok(VarOutcome {
                verdict: WireVarVerdict::Ignored { id, name },
                approval: None,
            })
        }
        ItemDecision::UseRule => match classify_var(policy, pending) {
            VarClassification::Decided(outcome) => Ok(outcome),
            VarClassification::Pending(p) => Err(ComposeError::use_rule_undecided(
                HookDomain::Var,
                format!("variable `{}`", p.name()),
            )),
        },
    }
}

/// Result of running a single pending var through the policy.
enum VarClassification {
    /// Policy reached a verdict.
    Decided(VarOutcome),
    /// Policy couldn't decide; pending is returned for the hook batch.
    Pending(PendingVar),
}

fn classify_var(policy: &VarsPolicy, pending: PendingVar) -> VarClassification {
    // The eager `to_owned()` is forced by `Decision::Ignored`: that
    // arm consumes the item without handing it back, so the name has
    // to be captured before `policy.check` takes ownership. The other
    // arms could reach the name through the returned `pv`.
    let name = pending.name().to_owned();
    let (id, pv) = pending.into_parts();
    // Vars whose value doesn't pull from the user's environment
    // (hardcoded literals, or `inherit-with-default` that fell back
    // to the default) aren't a data-leak vector — bypass the policy
    // and auto-approve. See `gate_vars` in compose.rs for the
    // symmetric loadout-side skip.
    if !pv.var().carries_user_data() {
        let approval = Some(SessionVar::from_provenanced(pv.clone()));
        return VarClassification::Decided(VarOutcome {
            verdict: PendingVar::reassemble(id, pv).into_approved_verdict(),
            approval,
        });
    }
    match policy.check(&name, pv) {
        CheckOutcome::Decided(Decision::Allowed(pv)) => {
            let approval = Some(SessionVar::from_provenanced(pv.clone()));
            VarClassification::Decided(VarOutcome {
                verdict: PendingVar::reassemble(id, pv).into_approved_verdict(),
                approval,
            })
        }
        CheckOutcome::Decided(Decision::Denied(pv)) => VarClassification::Decided(VarOutcome {
            verdict: PendingVar::reassemble(id, pv).into_denied_verdict(),
            approval: None,
        }),
        CheckOutcome::Decided(Decision::Ignored) => VarClassification::Decided(VarOutcome {
            verdict: WireVarVerdict::Ignored { id, name },
            approval: None,
        }),
        CheckOutcome::NeedsApproval(pv) => {
            VarClassification::Pending(PendingVar::reassemble(id, pv))
        }
    }
}

// =====================================================================
// Patches
// =====================================================================

fn gate_pending_patches(
    pending: Vec<WirePendingPatch>,
    policy: PatchesPolicy,
    hooks: &dyn PolicyHooks,
    options: ComposeOptions,
    combined_vars: &[SessionVar],
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<(Vec<WirePatchVerdict>, PatchesPolicy), ComposeError> {
    if pending.is_empty() {
        return Ok((Vec::new(), policy));
    }
    let home_fallback = env("HOME").ok();
    let home_fallback = home_fallback.as_deref();

    let mut expanded_policy = policy.expand_with(combined_vars, home_fallback)?;

    // Pass 1: walk each pending patch's source pattern, classify
    // every matched file. Unapproved files batch into one queue so
    // the hook prompts once per response.
    let (mut verdicts, unapproved) = enumerate_and_classify_patches(
        pending,
        &expanded_policy,
        combined_vars,
        home_fallback,
        options.follow_symlinks,
    )?;
    if unapproved.is_empty() {
        return Ok((verdicts, policy));
    }

    // Pass 2: prompt. If the hook updated the policy, re-expand
    // before applying decisions.
    let view: Vec<Unapproved<'_, camino::Utf8Path>> = unapproved
        .iter()
        .map(|p| Unapproved {
            item: p.file().user_facing().as_utf8_path(),
            source: p.file().source(),
        })
        .collect();
    let (decisions, policy, policy_updated) =
        crate::core::compose::prompt_patch_hook(hooks, policy, &view)?;
    if policy_updated {
        expanded_policy = policy.expand_with(combined_vars, home_fallback)?;
    }

    // Pass 3: apply.
    for (pending, decision) in unapproved.into_iter().zip(decisions) {
        verdicts.push(apply_patch_decision(&expanded_policy, pending, decision)?);
    }
    Ok((verdicts, policy))
}

/// Walk every pending patch's source pattern, run each matched file
/// through the policy, and partition into finished verdicts vs files
/// that need the hook.
fn enumerate_and_classify_patches(
    pending: Vec<WirePendingPatch>,
    policy: &ExpandedPatchesPolicy,
    combined_vars: &[SessionVar],
    home_fallback: Option<&str>,
    follow_symlinks: bool,
) -> Result<(Vec<WirePatchVerdict>, Vec<PendingPatchFile>), ComposeError> {
    let mut verdicts: Vec<WirePatchVerdict> = Vec::new();
    let mut unapproved: Vec<PendingPatchFile> = Vec::new();
    for p in pending {
        let id = p.id;
        let provenance: Source = p.source.into();
        let dest = PatchDest::try_new(p.destination.as_utf8_path().to_path_buf())
            .map_err(|source| ComposeError::InvalidPendingPatchDest { source })?;
        // Captured before `source_pattern` moves into the
        // `ProvenancedPatch` below; the "no host-anchored walk root"
        // error path names it so an operator sees which pattern
        // needs anchoring.
        let pattern_display = p.source_pattern.clone();
        // Client-response path handles daemon-side patches (Package /
        // Project) — user loadouts never reach this path (see
        // `daemon::composer`, which only accepts non-loadout
        // Composables). `ProvenancedPatch::new` stamps
        // `follow_symlinks: None`, which resolves to the compose
        // default at expand time.
        let pp = ProvenancedPatch::new(Patch::new(p.source_pattern, dest), provenance);
        let expanded =
            expand_patch_sources(vec![pp], combined_vars, home_fallback, follow_symlinks)?;
        // Capture the walk root before `enumerate_patch_files`
        // consumes `expanded`. Needed for the synthetic Ignored
        // verdict emitted below when the walk yields zero files.
        let synthetic_host_path = expanded
            .first()
            .and_then(|epp| epp.source.walk_root())
            .and_then(|hp| paths::HostAbsPath::try_new(hp.as_utf8_path().to_path_buf()).ok());
        let files = enumerate_patch_files(expanded)?;
        let mut emitted_for_id = false;
        for pf in files {
            emitted_for_id = true;
            match classify_patch_file(policy, PendingPatchFile::new(id, pf)) {
                PatchClassification::Decided(verdict) => verdicts.push(verdict),
                PatchClassification::Pending(p) => unapproved.push(p),
            }
        }
        // The daemon requires at least one verdict per pending id.
        // A pending patch whose walk matched zero files (e.g. the
        // path doesn't exist on this host, or the glob matched no
        // real files) still needs an entry — a synthetic `Ignored`
        // that references the walk root. If we can't even produce a
        // synthetic host path (walk root wasn't a canonical absolute
        // path — pathological patterns like `**/*`), surface a
        // client-side error naming the pending id and pattern rather
        // than sending an incomplete verdict and letting the daemon
        // reply with the undebuggable `verdict missing entry for
        // pending patch`.
        if !emitted_for_id {
            if let Some(host_path) = synthetic_host_path {
                verdicts.push(WirePatchVerdict::Ignored { id, host_path });
            } else {
                return Err(ComposeError::InvalidWireItem {
                    what: "pending patch has no host-anchored walk root",
                    context: format!(
                        "pending id {id:?}, source pattern `{pattern_display}` \
                         — the pattern's literal prefix is not an absolute \
                         host path, so no Ignored verdict can be emitted; \
                         make the source pattern host-anchored (e.g. `/…` \
                         or `~/…`)"
                    ),
                });
            }
        }
    }
    Ok((verdicts, unapproved))
}

/// Apply a hook's `ItemDecision` to a single pending patch file.
fn apply_patch_decision(
    policy: &ExpandedPatchesPolicy,
    pending: PendingPatchFile,
    decision: ItemDecision,
) -> Result<WirePatchVerdict, ComposeError> {
    match decision {
        ItemDecision::AllowOnce => Ok(pending.into_approved_verdict()),
        // `IgnoreOnce`: emit an `Ignored` wire verdict so the daemon
        // correlates the pending id and silently drops the item, same
        // as a policy `ignore` match.
        ItemDecision::IgnoreOnce => {
            let (id, pf) = pending.into_parts();
            let host_path = pf.target_path;
            Ok(WirePatchVerdict::Ignored { id, host_path })
        }
        ItemDecision::UseRule => match classify_patch_file(policy, pending) {
            PatchClassification::Decided(verdict) => Ok(verdict),
            PatchClassification::Pending(p) => Err(ComposeError::use_rule_undecided(
                HookDomain::Patch,
                format!("path `{}`", p.file().target_path.as_str()),
            )),
        },
    }
}

/// Result of running a single matched file through the patch policy.
enum PatchClassification {
    /// Policy reached a verdict.
    Decided(WirePatchVerdict),
    /// Policy couldn't decide; file is returned for the hook batch.
    Pending(PendingPatchFile),
}

fn classify_patch_file(
    policy: &ExpandedPatchesPolicy,
    pending: PendingPatchFile,
) -> PatchClassification {
    let (id, pf) = pending.into_parts();
    // Save the target path before `policy.check` consumes the file;
    // the Ignored arm doesn't get the file back and needs the path
    // to construct a verdict that the daemon can correlate.
    let saved_target = pf.target_path.clone();
    let link = pf
        .link_path
        .as_ref()
        .map(|p| p.as_utf8_path().to_path_buf());
    let target = pf.target_path.as_utf8_path().to_path_buf();
    match policy.check(link.as_deref(), &target, pf) {
        CheckOutcome::Decided(Decision::Allowed(pf)) => {
            PatchClassification::Decided(PendingPatchFile::new(id, pf).into_approved_verdict())
        }
        CheckOutcome::Decided(Decision::Denied(pf)) => {
            PatchClassification::Decided(PendingPatchFile::new(id, pf).into_denied_verdict())
        }
        CheckOutcome::Decided(Decision::Ignored) => {
            PatchClassification::Decided(WirePatchVerdict::Ignored {
                id,
                host_path: saved_target,
            })
        }
        CheckOutcome::NeedsApproval(pf) => {
            PatchClassification::Pending(PendingPatchFile::new(id, pf))
        }
    }
}
