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
//! Lifecycle hooks are pass-through — no per-hook policy exists, so
//! rejecting a hook means aborting the session.
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
use crate::core::policy::{ExpandedPatchPolicy, PatchPolicy, UserPolicy, VarsPolicy};
use crate::core::primitives::{Patch, PatchDest};
use crate::core::source::{Provenanced, ProvenancedPatch, Source};
use crate::wire::policy::{WirePatchVerdict, WireVarVerdict};
use crate::wire::primitives::{WirePendingPatch, WirePendingVar};
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
) -> Result<ContributionVerdict, ComposeError> {
    let session_id = response.session_id;
    let (vars_policy, patches_policy) = policy.into_parts();

    let var_out = gate_pending_vars(response.vars, vars_policy, hooks, env)?;

    let combined_vars: Vec<SessionVar> =
        gated_vars.iter().cloned().chain(var_out.approved).collect();

    let patch_verdicts = gate_pending_patches(
        response.patches,
        patches_policy,
        hooks,
        options,
        &combined_vars,
        env,
    )?;

    Ok(ContributionVerdict {
        session_id,
        vars: var_out.verdicts,
        patches: patch_verdicts,
    })
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
) -> Result<VarGateOutput, ComposeError> {
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
        return Ok(out);
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
    Ok(out)
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
    policy: PatchPolicy,
    hooks: &dyn PolicyHooks,
    options: ComposeOptions,
    combined_vars: &[SessionVar],
    env: &dyn Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<Vec<WirePatchVerdict>, ComposeError> {
    if pending.is_empty() {
        return Ok(Vec::new());
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
        return Ok(verdicts);
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
    Ok(verdicts)
}

/// Walk every pending patch's source pattern, run each matched file
/// through the policy, and partition into finished verdicts vs files
/// that need the hook.
fn enumerate_and_classify_patches(
    pending: Vec<WirePendingPatch>,
    policy: &ExpandedPatchPolicy,
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
        let pp = ProvenancedPatch::new(Patch::new(p.source_pattern, dest), provenance);
        let expanded = expand_patch_sources(vec![pp], combined_vars, home_fallback)?;
        let files = enumerate_patch_files(expanded, follow_symlinks)?;
        for pf in files {
            match classify_patch_file(policy, PendingPatchFile::new(id, pf)) {
                PatchClassification::Decided(verdict) => verdicts.push(verdict),
                PatchClassification::Pending(p) => unapproved.push(p),
            }
        }
    }
    Ok((verdicts, unapproved))
}

/// Apply a hook's `ItemDecision` to a single pending patch file.
fn apply_patch_decision(
    policy: &ExpandedPatchPolicy,
    pending: PendingPatchFile,
    decision: ItemDecision,
) -> Result<WirePatchVerdict, ComposeError> {
    match decision {
        ItemDecision::AllowOnce => Ok(pending.into_approved_verdict()),
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
    policy: &ExpandedPatchPolicy,
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
