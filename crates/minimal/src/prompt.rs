//! Interactive policy prompts for `min session activate`.
//!
//! When the daemon returns a pending item (a Project or Package
//! contribution the user's [`UserPolicy`] can't auto-decide), the
//! composer asks a [`PolicyHooks`] implementation what to do. This
//! module provides two:
//!
//! - [`InteractivePrompt`] — the default: shows an `inquire::Select`
//!   for each item with six actions (Allow once, Allow permanent,
//!   Ignore once, Ignore permanent, Abort, Deny permanent). The
//!   permanent actions mutate the passed-in narrow policy so
//!   `handle_response` / `UserComposer::compose` return a policy the
//!   caller can persist.
//! - [`NoPromptHook`] — the `--no-prompt` (or non-TTY) variant:
//!   never prompts, always aborts on any unapproved item with an
//!   error message that includes a `user_policy.toml` snippet
//!   showing every item the user would need to allowlist.
//!
//! [`UserPolicy`]: sessions::core::policy::UserPolicy
//! [`PolicyHooks`]: sessions::core::hooks::PolicyHooks

use std::cell::RefCell;
#[cfg(test)]
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};

use sessions::core::decision::ItemDecision;
use sessions::core::hooks::{HookResult, PolicyHooks, Unapproved};
use sessions::core::policy::{HooksPolicy, PatchesPolicy, VarNameGlobs, VarsPolicy};
use sessions::core::source::Source;

/// One choice a user makes at a prompt. Names carry both intent
/// ("allow/ignore/deny") and scope ("once" vs. "permanent").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UserChoice {
    /// Approve this item for this activation only.
    AllowOnce,
    /// Approve this item and append its name/path to `policy.allow`.
    AllowPermanent,
    /// Silently drop this item for this activation only.
    IgnoreOnce,
    /// Silently drop this item and append its name/path to
    /// `policy.ignore`.
    IgnorePermanent,
    /// Halt this activation without recording anything.
    Abort,
    /// Halt this activation *and* append the item to `policy.deny`
    /// so future activations reject it before even reaching the
    /// prompt.
    DenyPermanent,
}

impl UserChoice {
    /// Label rendered as the `inquire::Select` option.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::AllowOnce => "Allow once",
            Self::AllowPermanent => "Allow permanent (add to user_policy.toml)",
            Self::IgnoreOnce => "Ignore once",
            Self::IgnorePermanent => "Ignore permanent (add to user_policy.toml)",
            Self::Abort => "Abort activation",
            Self::DenyPermanent => "Deny permanent (add to user_policy.toml)",
        }
    }

    /// The six choices in display order. Grouped by intent: each
    /// once/permanent pair stays together, safe defaults on top.
    pub(crate) fn all() -> &'static [Self] {
        &[
            Self::AllowOnce,
            Self::AllowPermanent,
            Self::IgnoreOnce,
            Self::IgnorePermanent,
            Self::Abort,
            Self::DenyPermanent,
        ]
    }

    /// Choices available when `user_policy.toml` isn't writable —
    /// the three permanent actions require a policy edit and are
    /// filtered out.
    pub(crate) fn readonly_only() -> &'static [Self] {
        &[Self::AllowOnce, Self::IgnoreOnce, Self::Abort]
    }
}

impl std::fmt::Display for UserChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Abstraction over "ask the user for one choice." Real code uses
/// `inquire`; tests inject a scripted answer stream.
pub(crate) trait Prompter {
    /// Show `message` and let the user pick one of `options`.
    /// Returns the chosen [`UserChoice`] or an IO error if the
    /// terminal can't be driven (e.g. stdin closed mid-prompt).
    fn ask(&self, message: &str, options: &[UserChoice]) -> io::Result<UserChoice>;
}

/// Real `inquire`-backed prompter. Only used by the default
/// [`InteractivePrompt::new`] constructor.
pub(crate) struct InquirePrompter;

impl Prompter for InquirePrompter {
    fn ask(&self, message: &str, options: &[UserChoice]) -> io::Result<UserChoice> {
        // Six fixed choices: type-to-filter would be noise, so filtering
        // stays off. The cursor starts on index 0 ("Allow once", the
        // safest one-shot action), giving a habitual user fast
        // Enter-through. Esc (OperationCanceled) and Ctrl-C
        // (OperationInterrupted) surface as errors so a dismissed prompt
        // fails the activation, which then runs its abort cleanup.
        inquire::Select::new(message, options.to_vec())
            .without_filtering()
            .prompt()
            .map_err(io::Error::other)
    }
}

/// Test-only prompter that drains a pre-baked answer queue.
///
/// `next_choice()` returns the front of the queue for each `ask`
/// call. Panics if the queue empties before all prompts complete —
/// a test that requests more prompts than answers is buggy.
#[cfg(test)]
pub(crate) struct ScriptedPrompter {
    answers: RefCell<VecDeque<UserChoice>>,
}

#[cfg(test)]
impl ScriptedPrompter {
    pub(crate) fn new(answers: impl IntoIterator<Item = UserChoice>) -> Self {
        Self {
            answers: RefCell::new(answers.into_iter().collect()),
        }
    }
}

#[cfg(test)]
impl Prompter for ScriptedPrompter {
    fn ask(&self, _message: &str, _options: &[UserChoice]) -> io::Result<UserChoice> {
        self.answers
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| io::Error::other("ScriptedPrompter ran out of answers"))
    }
}

/// A [`PolicyHooks`] implementation that walks the user through each
/// unapproved item interactively.
///
/// Construct via [`Self::new`] (uses `inquire` + resolves the
/// read-only bit from the on-disk `user_policy.toml`) or, in tests,
/// via [`Self::with_prompter`].
///
/// Policy mutations from the "permanent" choices live in interior
/// [`RefCell`]s so a `DenyPermanent` — which returns
/// [`HookResult::Abort`] and thus can't send an `updated_policy` back
/// through the composer — still survives to
/// [`Self::into_final_policy`]. The caller reads final state from the
/// hook regardless of whether activation succeeded or aborted.
pub struct InteractivePrompt {
    prompter: Box<dyn Prompter>,
    /// True when `user_policy.toml` (or the parent directory, if the
    /// file doesn't exist yet) is writable. Filters permanent choices
    /// when false — a rule the user picks would fail to persist, so
    /// don't offer it.
    can_persist: bool,
    /// Accumulated vars-side mutations. Starts at the initial
    /// [`VarsPolicy`] passed to [`Self::new`]; each
    /// `on_var_unapproved` call reads from and writes back to this
    /// cell. Extracted by [`Self::into_final_policy`].
    vars_policy: RefCell<VarsPolicy>,
    /// Same shape as `vars_policy`, for the patches side.
    patches_policy: RefCell<PatchesPolicy>,
    /// Same shape again, for the lifecycle-hooks side.
    hooks_policy: RefCell<HooksPolicy>,
}

impl InteractivePrompt {
    /// Real constructor: `inquire` prompter + read-only detection
    /// against `policy_path`. `initial` seeds the internal policy
    /// state so the first hook call sees the same view as the
    /// composer.
    #[must_use]
    pub fn new(policy_path: &Path, initial: sessions::core::policy::UserPolicy) -> Self {
        let (vars, patches, hooks) = initial.into_parts();
        Self {
            prompter: Box::new(InquirePrompter),
            can_persist: is_writable(policy_path),
            vars_policy: RefCell::new(vars),
            patches_policy: RefCell::new(patches),
            hooks_policy: RefCell::new(hooks),
        }
    }

    /// Consume the hook and return the accumulated [`UserPolicy`].
    /// Reassembles the two narrow policies into the wire form
    /// [`crate::config::save_user_policy`] expects. Safe to call
    /// after either an `Ok` or an `Err` return from
    /// `drive_pending_to_active`; the mutations live in
    /// [`RefCell`]s that don't care which happened.
    #[must_use]
    pub fn into_final_policy(self) -> sessions::core::policy::UserPolicy {
        sessions::core::policy::UserPolicy::empty()
            .with_vars(self.vars_policy.into_inner())
            .with_patches(self.patches_policy.into_inner())
            .with_hooks(self.hooks_policy.into_inner())
    }

    /// Test seam: injectable prompter + explicit `can_persist`.
    /// Starts with an empty policy so per-test setup is minimal.
    #[cfg(test)]
    fn with_prompter(prompter: Box<dyn Prompter>, can_persist: bool) -> Self {
        Self {
            prompter,
            can_persist,
            vars_policy: RefCell::new(VarsPolicy::empty()),
            patches_policy: RefCell::new(PatchesPolicy::empty()),
            hooks_policy: RefCell::new(HooksPolicy::empty()),
        }
    }

    /// Available choices for the current filesystem state — drops
    /// permanent actions when `can_persist` is false.
    fn choices(&self) -> &'static [UserChoice] {
        if self.can_persist {
            UserChoice::all()
        } else {
            UserChoice::readonly_only()
        }
    }
}

/// Whether the current user could actually write `path` — the guard
/// for offering permanent policy edits.
///
/// The check has to reflect the *effective* access of the caller,
/// not just the file's mode bits: a root-owned `user_policy.toml`
/// with mode `0o644` looks writable to `std::fs::Permissions::readonly`
/// (owner-write is set) but a non-root user can't rewrite it, and
/// offering the permanent choices only for `save_user_policy` to die
/// with `EACCES` after the daemon has been prompted through is the
/// specific outcome this filter exists to avoid. `access(2)` with
/// `W_OK` asks the kernel the same question `open(..., O_WRONLY)`
/// would answer.
///
/// If `path` doesn't exist, walk *every* missing ancestor: a fresh
/// install where `~/.config/minimal/` doesn't exist yet still needs
/// the permanent choices offered, because `save_user_policy` calls
/// `create_dir_all(parent)` and lands the file only if the first
/// existing ancestor is writable.
///
/// Falls back to "not writable" on any unexpected failure — better
/// to hide choices we can't honor than to promise persistence and
/// fail.
fn is_writable(path: &Path) -> bool {
    use nix::unistd::{AccessFlags, access};
    match access(path, AccessFlags::W_OK) {
        Ok(()) => true,
        Err(nix::errno::Errno::ENOENT) => {
            let mut cur = path.parent();
            while let Some(dir) = cur {
                // A relative path like `user_policy.toml` has parent
                // `""` (per `Path::parent` semantics). Treat empty as
                // "the current working directory" via `.` so
                // `access(2)` gets a real path to consult instead of
                // returning ENOENT and terminating the walk with a
                // spurious false. Without this, any caller resolving
                // the policy to a bare filename (test harnesses,
                // `MINIMAL_CONFIG_DIR=.`) permanently loses the
                // *Permanent choices.
                let probe: &Path = if dir.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    dir
                };
                match access(probe, AccessFlags::W_OK) {
                    Ok(()) => return true,
                    Err(nix::errno::Errno::ENOENT) => cur = dir.parent(),
                    Err(_) => return false,
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// Human-readable name for a provenance source, e.g. `Project /foo`
/// or `Package "go"`. Fed into the prompt message so the user knows
/// who's asking.
fn source_label(source: &Source) -> String {
    // `Source` is `#[non_exhaustive]`; the wildcard covers future
    // variants without silently mislabelling them.
    match source {
        Source::Project { path } => format!("Project at {}", path.as_utf8_path().as_str()),
        Source::Package { name } => format!("Package `{name}`"),
        Source::UserLoadout { name } => format!("Loadout `{name}`"),
        _ => "Unknown source".to_string(),
    }
}

impl PolicyHooks for InteractivePrompt {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        // Ignore the passed-in `policy` — we track the mutated view
        // in `self.vars_policy`, which starts at the initial policy
        // and folds in mutations across every hook call. This is what
        // lets `DenyPermanent` (which returns `Abort` and thus can't
        // send `updated_policy` back through the composer) still
        // survive to `into_final_policy`.
        let choices = self.choices();
        let mut decisions = Vec::with_capacity(items.len());
        let mut policy_touched = false;
        let mut policy = self.vars_policy.borrow_mut();
        for item in items {
            let name = item.item();
            let msg = format!(
                "{} wants to read `{name}` from your environment and pass it into the session",
                source_label(item.source())
            );
            let choice = match self.prompter.ask(&msg, choices) {
                Ok(c) => c,
                // Prompter I/O failure surfaces as Abort — safer than
                // silently allowing.
                Err(_) => return HookResult::Abort,
            };
            match apply_var_choice(&mut policy, name, choice, &mut policy_touched) {
                VarStep::Decision(d) => decisions.push(d),
                VarStep::Abort => return HookResult::Abort,
            }
        }
        if policy_touched {
            HookResult::decided_with_policy(decisions, policy.clone())
        } else {
            HookResult::decided(decisions)
        }
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        let choices = self.choices();
        let mut decisions = Vec::with_capacity(items.len());
        let mut policy_touched = false;
        let mut policy = self.patches_policy.borrow_mut();
        for item in items {
            let path = item.item();
            let msg = format!(
                "{} wants to patch `{}`",
                source_label(item.source()),
                path.as_str()
            );
            let choice = match self.prompter.ask(&msg, choices) {
                Ok(c) => c,
                Err(_) => return HookResult::Abort,
            };
            match apply_patch_choice(&mut policy, path.as_str(), choice, &mut policy_touched) {
                PatchStep::Decision(d) => decisions.push(d),
                PatchStep::Abort => return HookResult::Abort,
            }
        }
        if policy_touched {
            HookResult::decided_with_policy(decisions, policy.clone())
        } else {
            HookResult::decided(decisions)
        }
    }

    fn on_hook_unapproved(
        &self,
        _policy: HooksPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        let choices = self.choices();
        let mut decisions = Vec::with_capacity(items.len());
        let mut policy_touched = false;
        let mut policy = self.hooks_policy.borrow_mut();
        for item in items {
            let root = item.item();
            // Worded to say what approval actually grants. The other
            // two domains move data; this one runs code, and a prompt
            // that read like "wants to use lifecycle hooks" would
            // understate what the user is agreeing to.
            let msg = format!(
                "The project at `{}` wants to run its own scripts inside the session \
                 (lifecycle hooks). This executes arbitrary code from that project.",
                root.as_str()
            );
            let choice = match self.prompter.ask(&msg, choices) {
                Ok(c) => c,
                Err(_) => return HookResult::Abort,
            };
            match apply_hook_choice(&mut policy, root.as_str(), choice, &mut policy_touched) {
                HookStep::Decision(d) => decisions.push(d),
                HookStep::Abort => return HookResult::Abort,
            }
        }
        if policy_touched {
            HookResult::decided_with_policy(decisions, policy.clone())
        } else {
            HookResult::decided(decisions)
        }
    }
}

// =====================================================================
// Per-choice → per-decision + policy-mutation logic
// =====================================================================

/// Outcome of applying a var-side [`UserChoice`]: either a per-item
/// decision or a batch abort.
enum VarStep {
    Decision(ItemDecision),
    Abort,
}

/// Outcome of applying a patch-side [`UserChoice`]: same shape as
/// [`VarStep`], separated so the two callers can't accidentally
/// swap them.
enum PatchStep {
    Decision(ItemDecision),
    Abort,
}

/// Fold a [`UserChoice`] into a [`VarStep`] + policy mutation. The
/// `touched` flag flips to true whenever `policy` is mutated so the
/// caller can decide whether to send an `updated_policy` back to the
/// composer.
fn apply_var_choice(
    policy: &mut VarsPolicy,
    name: &str,
    choice: UserChoice,
    touched: &mut bool,
) -> VarStep {
    // Any of the `Permanent` arms can hit
    // [`append_var_pattern`]'s glob-parse failure — a var name
    // containing `[` / `\` etc. doesn't compile into `VarNameGlobs`.
    // Falling through to `UseRule` then dead-ends the composer with
    // `use_rule_undecided` because the reclassification can't
    // possibly find a rule that isn't there. Instead, when the
    // allow/ignore permanent pattern can't be persisted, downgrade
    // to the closest `Once` decision so the current activation still
    // proceeds and warn the operator that the rule didn't stick.
    let downgrade_once = |name: &str, bucket: &'static str| {
        eprintln!(
            "warning: could not persist {bucket} rule for `{name}` — \
             the name isn't a valid glob pattern; applying to this \
             activation only. Add the rule to `user_policy.toml` by \
             hand if you want it to stick."
        );
    };
    match choice {
        UserChoice::AllowOnce => VarStep::Decision(ItemDecision::AllowOnce),
        UserChoice::IgnoreOnce => VarStep::Decision(ItemDecision::IgnoreOnce),
        UserChoice::AllowPermanent => {
            if append_var_pattern(policy, VarBucket::Allow, name) {
                *touched = true;
                VarStep::Decision(ItemDecision::UseRule)
            } else {
                downgrade_once(name, "allow");
                VarStep::Decision(ItemDecision::AllowOnce)
            }
        }
        UserChoice::IgnorePermanent => {
            if append_var_pattern(policy, VarBucket::Ignore, name) {
                *touched = true;
                VarStep::Decision(ItemDecision::UseRule)
            } else {
                downgrade_once(name, "ignore");
                VarStep::Decision(ItemDecision::IgnoreOnce)
            }
        }
        UserChoice::Abort => VarStep::Abort,
        UserChoice::DenyPermanent => {
            // `deny` always aborts the activation regardless of
            // persistence outcome. `touched` only flips when we
            // actually saved a rule. On persistence failure, the
            // *deny for this activation* is still delivered (via
            // `Abort`), so the warning here has to be about the
            // *rule not sticking* — not about "applying to this
            // activation only" like the allow/ignore downgrade
            // messages, which would imply the session came up.
            if append_var_pattern(policy, VarBucket::Deny, name) {
                *touched = true;
            } else {
                eprintln!(
                    "warning: could not persist deny rule for `{name}` — \
                     the name isn't a valid glob pattern; aborting this \
                     activation anyway. Add the rule to `user_policy.toml` \
                     by hand if you want it to stick for future activations."
                );
            }
            VarStep::Abort
        }
    }
}

/// Fold a [`UserChoice`] into a [`PatchStep`] + policy mutation.
/// Patch patterns are stored raw: we push the exact resolved
/// absolute path the walker produced. Fancier pattern editing
/// (glob-ification, `~/` conversion) is a future feature.
fn apply_patch_choice(
    policy: &mut PatchesPolicy,
    path: &str,
    choice: UserChoice,
    touched: &mut bool,
) -> PatchStep {
    match choice {
        UserChoice::AllowOnce => PatchStep::Decision(ItemDecision::AllowOnce),
        UserChoice::IgnoreOnce => PatchStep::Decision(ItemDecision::IgnoreOnce),
        UserChoice::AllowPermanent => {
            *policy = append_patch_pattern(policy.clone(), PatchBucket::Allow, path);
            *touched = true;
            PatchStep::Decision(ItemDecision::UseRule)
        }
        UserChoice::IgnorePermanent => {
            *policy = append_patch_pattern(policy.clone(), PatchBucket::Ignore, path);
            *touched = true;
            PatchStep::Decision(ItemDecision::UseRule)
        }
        UserChoice::Abort => PatchStep::Abort,
        UserChoice::DenyPermanent => {
            *policy = append_patch_pattern(policy.clone(), PatchBucket::Deny, path);
            *touched = true;
            PatchStep::Abort
        }
    }
}

/// Outcome of applying a hooks-side [`UserChoice`]. Same shape as
/// [`VarStep`] and [`PatchStep`].
enum HookStep {
    Decision(ItemDecision),
    Abort,
}

/// Apply one [`UserChoice`] to the hooks policy for a project root.
///
/// The permanent variants record the project root verbatim, so
/// approving once covers every hook that project declares now and
/// later. That is the intended grain: the user is trusting the
/// project, not auditing individual scripts, and a per-script rule
/// would silently lapse the moment the project added another.
fn apply_hook_choice(
    policy: &mut HooksPolicy,
    root: &str,
    choice: UserChoice,
    touched: &mut bool,
) -> HookStep {
    match choice {
        UserChoice::AllowOnce => HookStep::Decision(ItemDecision::AllowOnce),
        UserChoice::IgnoreOnce => HookStep::Decision(ItemDecision::IgnoreOnce),
        UserChoice::AllowPermanent => {
            *policy = append_hook_pattern(policy.clone(), HookBucket::Allow, root);
            *touched = true;
            HookStep::Decision(ItemDecision::UseRule)
        }
        UserChoice::IgnorePermanent => {
            *policy = append_hook_pattern(policy.clone(), HookBucket::Ignore, root);
            *touched = true;
            HookStep::Decision(ItemDecision::UseRule)
        }
        UserChoice::Abort => HookStep::Abort,
        UserChoice::DenyPermanent => {
            *policy = append_hook_pattern(policy.clone(), HookBucket::Deny, root);
            *touched = true;
            HookStep::Abort
        }
    }
}

enum HookBucket {
    Allow,
    Deny,
    Ignore,
}

/// Append `root` as a pattern into the requested hooks-policy bucket.
fn append_hook_pattern(policy: HooksPolicy, bucket: HookBucket, root: &str) -> HooksPolicy {
    // Stored as a literal, not as the pattern it would otherwise be
    // read as. The user picked one project at the prompt; a raw path
    // containing glob metacharacters would either match its siblings
    // too — approving code execution nobody was asked about — or match
    // nothing, leaving a rule that silently never fires. See
    // [`literal_policy_pattern`].
    let root = sessions::core::expansion::literal_policy_pattern(root);
    let extend = |existing: &[String]| -> Vec<String> {
        existing
            .iter()
            .cloned()
            .chain(std::iter::once(root.clone()))
            .collect()
    };
    match bucket {
        HookBucket::Allow => {
            let p = extend(policy.allow());
            policy.with_allow(p)
        }
        HookBucket::Deny => {
            let p = extend(policy.deny());
            policy.with_deny(p)
        }
        HookBucket::Ignore => {
            let p = extend(policy.ignore());
            policy.with_ignore(p)
        }
    }
}

enum VarBucket {
    Allow,
    Deny,
    Ignore,
}

enum PatchBucket {
    Allow,
    Deny,
    Ignore,
}

/// Append `name` as a glob pattern into the requested `bucket`.
/// Returns `true` on success, `false` if the glob failed to parse —
/// the caller has to decide what to do about that (the permanent
/// rule wasn't persisted).
fn append_var_pattern(policy: &mut VarsPolicy, bucket: VarBucket, name: &str) -> bool {
    // Var names are trivial globs (no metacharacters expected in
    // practice, but the append path is glob-typed). `with_pattern`
    // parses and rebuilds the compiled set.
    let (current, take_bucket): (&VarNameGlobs, fn(&mut VarsPolicy, VarNameGlobs)) = match bucket {
        VarBucket::Allow => (policy.allow(), |p, g| {
            let old = std::mem::take(p);
            *p = old.with_allow(g);
        }),
        VarBucket::Deny => (policy.deny(), |p, g| {
            let old = std::mem::take(p);
            *p = old.with_deny(g);
        }),
        VarBucket::Ignore => (policy.ignore(), |p, g| {
            let old = std::mem::take(p);
            *p = old.with_ignore(g);
        }),
    };
    match current.clone().with_pattern(name) {
        Ok(updated) => {
            take_bucket(policy, updated);
            true
        }
        Err(_) => false,
    }
}

fn append_patch_pattern(policy: PatchesPolicy, bucket: PatchBucket, path: &str) -> PatchesPolicy {
    // Same literal-not-pattern reasoning as `append_hook_pattern`. A
    // patch moves data rather than running it, so the stakes are lower
    // — but a rule that silently never matches is the same bug either
    // way, and the user picked one file.
    let path = &sessions::core::expansion::literal_policy_pattern(path);
    match bucket {
        PatchBucket::Allow => {
            let patterns: Vec<String> = policy
                .allow()
                .iter()
                .cloned()
                .chain(std::iter::once(path.to_owned()))
                .collect();
            policy.with_allow(patterns)
        }
        PatchBucket::Deny => {
            let patterns: Vec<String> = policy
                .deny()
                .iter()
                .cloned()
                .chain(std::iter::once(path.to_owned()))
                .collect();
            policy.with_deny(patterns)
        }
        PatchBucket::Ignore => {
            let patterns: Vec<String> = policy
                .ignore()
                .iter()
                .cloned()
                .chain(std::iter::once(path.to_owned()))
                .collect();
            policy.with_ignore(patterns)
        }
    }
}

// =====================================================================
// --no-prompt / non-TTY variant
// =====================================================================

/// A [`PolicyHooks`] impl that never prompts. Aborts on any
/// unapproved item after building a `user_policy.toml` snippet the
/// operator can paste to make the activation succeed.
///
/// Selected when `--no-prompt` is passed or when stdin isn't a TTY.
pub struct NoPromptHook {
    /// Accumulates var names and patch paths that would have been
    /// prompted, so the error message can enumerate them.
    ///
    /// `RefCell` because [`PolicyHooks`] takes `&self`. Only touched
    /// on the hook's own thread; no cross-thread hazard.
    seen: RefCell<UnapprovedSummary>,
}

/// The names/paths a [`NoPromptHook`] pass would have prompted for,
/// separated so the emitted TOML snippet groups them under
/// `[vars] allow` vs `[patches] allow`.
#[derive(Default)]
pub struct UnapprovedSummary {
    vars: Vec<String>,
    patches: Vec<String>,
    hooks: Vec<String>,
}

impl UnapprovedSummary {
    /// Format the accumulated items as a `user_policy.toml` snippet
    /// the operator can paste. Empty sections are omitted so the
    /// snippet stays minimal. Strings are emitted through
    /// [`toml_edit`] so bytes that need TOML escaping (`"`, `\`,
    /// newline, control chars) come out as valid TOML — patch paths
    /// can carry any of those on Unix and a naive `push_str` would
    /// hand the operator a snippet that no longer parses.
    #[must_use]
    pub fn as_toml_snippet(&self) -> String {
        let mut doc = toml_edit::DocumentMut::new();
        if !self.vars.is_empty() {
            let mut vars = toml_edit::Table::new();
            let mut allow = toml_edit::Array::new();
            for name in &self.vars {
                allow.push(name.as_str());
            }
            vars.insert("allow", toml_edit::value(allow));
            doc.insert("vars", toml_edit::Item::Table(vars));
        }
        if !self.patches.is_empty() {
            let mut patches = toml_edit::Table::new();
            let mut allow = toml_edit::Array::new();
            for path in &self.patches {
                allow.push(path.as_str());
            }
            patches.insert("allow", toml_edit::value(allow));
            doc.insert("patches", toml_edit::Item::Table(patches));
        }
        if !self.hooks.is_empty() {
            let mut hooks = toml_edit::Table::new();
            let mut allow = toml_edit::Array::new();
            for root in &self.hooks {
                allow.push(root.as_str());
            }
            hooks.insert("allow", toml_edit::value(allow));
            doc.insert("hooks", toml_edit::Item::Table(hooks));
        }
        doc.to_string()
    }

    /// Total items seen — used to size the error message ("N items
    /// would require approval").
    #[must_use]
    pub fn count(&self) -> usize {
        self.vars.len() + self.patches.len() + self.hooks.len()
    }
}

impl NoPromptHook {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: RefCell::new(UnapprovedSummary::default()),
        }
    }

    /// Consume the hook after `handle_response` / `compose` has run
    /// and yield the summary. Callers use this to build the final
    /// error message.
    #[must_use]
    pub fn into_summary(self) -> UnapprovedSummary {
        self.seen.into_inner()
    }
}

impl Default for NoPromptHook {
    fn default() -> Self {
        Self::new()
    }
}

/// Insert `item` into `seen` iff it isn't already present. Keeps
/// `--no-prompt` summaries stable when two packages want the same
/// var or patch: without this, a snippet like
/// `allow = ["DIAGRAM", "DIAGRAM"]` would go into `user_policy.toml`
/// and either fail to parse cleanly or leave duplicate entries in
/// the resulting `VarNameGlobs::raw_patterns()`.
fn insert_unique(seen: &mut Vec<String>, item: String) {
    if !seen.iter().any(|existing| existing == &item) {
        seen.push(item);
    }
}

impl PolicyHooks for NoPromptHook {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        // Fake-approve every item so `handle_response` keeps going
        // and the patch hook fires too — otherwise the operator's
        // `--no-prompt` snippet would only list the vars and hide
        // half the required policy edits. The caller (cmd_activate)
        // is responsible for checking `into_summary().count() > 0`
        // *before* actually submitting the verdict, so a fake
        // approval here never reaches the daemon as a real one.
        let mut seen = self.seen.borrow_mut();
        for item in items {
            insert_unique(&mut seen.vars, item.item().to_owned());
        }
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        let mut seen = self.seen.borrow_mut();
        for item in items {
            insert_unique(&mut seen.patches, item.item().as_str().to_owned());
        }
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }

    /// Records each project whose hooks would need approval and
    /// fake-approves, exactly as the other two domains do — the caller
    /// checks `into_summary().count()` and aborts before any verdict
    /// reaches the daemon, so this never grants execution.
    fn on_hook_unapproved(
        &self,
        _policy: HooksPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        let mut seen = self.seen.borrow_mut();
        for item in items {
            insert_unique(&mut seen.hooks, item.item().as_str().to_owned());
        }
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }
}

// =====================================================================
// Persistence
// =====================================================================

/// Serialize `policy` to TOML and write it atomically to
/// `policy_path`, **preserving** any comments and formatting the
/// user had in the existing file. The write is `write-tmp` +
/// `rename` so an interrupted process doesn't leave a half-written
/// policy on disk, and the previous contents survive as
/// `policy_path.bak` for one activation's worth of undo.
///
/// Uses `toml_edit` under the hood: parses the existing file into a
/// format-preserving document, upserts each allow/deny/ignore array
/// under `[vars]` and `[patches]`, and leaves untouched sections
/// (plus every comment) intact. A fresh install (no existing file)
/// starts with an empty document.
///
/// Empty rule lists are omitted rather than written as `allow = []`
/// — that behavior matches the serde `skip_serializing_if` default
/// and keeps a minimal policy from bloating with empty sections.
///
/// # Errors
///
/// Any I/O failure during backup, tempfile, or rename; or a parse
/// failure on the existing file (which shouldn't happen unless the
/// user hand-broke it since the last load).
pub fn save_user_policy(
    policy_path: &Path,
    policy: &sessions::core::policy::UserPolicy,
) -> Result<(), anyhow::Error> {
    // Parse the existing file if present. A missing file yields an
    // empty document, which the merge logic treats identically to a
    // freshly-created file.
    let existing = match std::fs::read_to_string(policy_path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::anyhow!("reading {}: {e}", policy_path.display()));
        }
    };
    let mut doc: toml_edit::DocumentMut = existing
        .parse()
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", policy_path.display()))?;

    merge_policy_into_document(&mut doc, policy);

    let serialized = doc.to_string();

    // Ensure the parent dir exists. `create_dir_all` is idempotent
    // so a re-run doesn't churn.
    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;
    }

    // Backup the existing file. On a fresh install nothing to back up.
    if policy_path.exists() {
        let bak = with_extension_bak(policy_path);
        std::fs::copy(policy_path, &bak)
            .map_err(|e| anyhow::anyhow!("backing up to {}: {e}", bak.display()))?;
    }

    let tmp = with_extension_tmp(policy_path);
    // Unlink the tmp on any early return between `write` and a
    // successful `rename` — a failed rename (cross-device, EACCES,
    // ENOSPC) would otherwise leave a stale `<policy>.tmp` next to
    // the real file every time the caller aborts the activation.
    // Uses `RemoveOnDrop` rather than a manual `let _ =
    // std::fs::remove_file(&tmp)` on every error branch so we can't
    // forget it if a new fallible step is inserted later. On the
    // rename-succeeded path the guard is disarmed so the moved file
    // stays put.
    let mut guard = RemoveOnDrop::arm(&tmp);
    std::fs::write(&tmp, serialized.as_bytes())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, policy_path).map_err(|e| {
        anyhow::anyhow!(
            "atomic rename {} → {}: {e}",
            tmp.display(),
            policy_path.display()
        )
    })?;
    guard.disarm();
    Ok(())
}

/// Deletes `path` when dropped unless [`Self::disarm`] was called.
/// Used by [`save_user_policy`] to guarantee the tmp file doesn't
/// outlive a failed rename.
struct RemoveOnDrop<'p> {
    path: &'p Path,
    armed: bool,
}

impl<'p> RemoveOnDrop<'p> {
    fn arm(path: &'p Path) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RemoveOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// Upsert the nine rule arrays (`vars`, `patches`, and `hooks`, each
/// with `allow`/`deny`/`ignore`) from `policy` into `doc`, replacing
/// each in place while leaving surrounding structure, comments, and
/// unrelated keys intact. Empty arrays are removed rather than
/// written as `[]` so a minimal policy doesn't render bloated
/// sections.
fn merge_policy_into_document(
    doc: &mut toml_edit::DocumentMut,
    policy: &sessions::core::policy::UserPolicy,
) {
    let vars = policy.vars();
    upsert_string_array(doc, "vars", "allow", vars.allow().raw_patterns());
    upsert_string_array(doc, "vars", "deny", vars.deny().raw_patterns());
    upsert_string_array(doc, "vars", "ignore", vars.ignore().raw_patterns());

    let patches = policy.patches();
    upsert_string_array(doc, "patches", "allow", patches.allow());
    upsert_string_array(doc, "patches", "deny", patches.deny());
    upsert_string_array(doc, "patches", "ignore", patches.ignore());

    let hooks = policy.hooks();
    upsert_string_array(doc, "hooks", "allow", hooks.allow());
    upsert_string_array(doc, "hooks", "deny", hooks.deny());
    upsert_string_array(doc, "hooks", "ignore", hooks.ignore());

    // Drop sections that end up empty. Keeps the file minimal after a
    // rule the user hand-added gets emptied by some future policy
    // operation (defensive — today's flow only appends, never
    // removes).
    remove_empty_section(doc, "vars");
    remove_empty_section(doc, "patches");
    remove_empty_section(doc, "hooks");
}

fn upsert_string_array(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    key: &str,
    values: &[String],
) {
    if values.is_empty() {
        // Remove the key entirely — matches serde
        // `skip_serializing_if = "Vec::is_empty"` semantics.
        if let Some(table) = doc.get_mut(section).and_then(|item| item.as_table_mut()) {
            table.remove(key);
        }
        return;
    }
    // Ensure the [section] table exists. A freshly-created table
    // gets an empty decor, so headings/comments above the section
    // header stay attached to whatever was written before (if any).
    if doc.get(section).is_none() {
        doc.insert(section, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let Some(table) = doc.get_mut(section).and_then(|item| item.as_table_mut()) else {
        // Existing entry for `section` isn't a table — the user
        // hand-edited it into something weird. Skip rather than
        // clobber; the composition still runs, they just don't
        // get their new rule persisted.
        return;
    };
    // Prefer mutating an existing array in place so the key's
    // surrounding decor (comments above it, spacing, inline
    // whitespace) survives. Fall back to insert only when the key
    // is brand new — there's no existing decor to preserve.
    if let Some(existing) = table.get_mut(key).and_then(toml_edit::Item::as_array_mut) {
        existing.clear();
        for v in values {
            existing.push(v.as_str());
        }
        return;
    }
    let mut arr = toml_edit::Array::new();
    for v in values {
        arr.push(v.as_str());
    }
    table.insert(key, toml_edit::value(arr));
}

fn remove_empty_section(doc: &mut toml_edit::DocumentMut, section: &str) {
    let Some(table) = doc.get(section).and_then(|item| item.as_table()) else {
        return;
    };
    if table.is_empty() {
        doc.remove(section);
    }
}

fn with_extension_bak(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let new_name = match path.file_name() {
        Some(name) => {
            let mut n = name.to_os_string();
            n.push(".bak");
            n
        }
        None => "user_policy.toml.bak".into(),
    };
    p.set_file_name(new_name);
    p
}

fn with_extension_tmp(path: &Path) -> PathBuf {
    let mut p = path.to_path_buf();
    let new_name = match path.file_name() {
        Some(name) => {
            let mut n = name.to_os_string();
            n.push(".tmp");
            n
        }
        None => "user_policy.toml.tmp".into(),
    };
    p.set_file_name(new_name);
    p
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::core::policy::UserPolicy;
    use tempfile::TempDir;

    fn project_source() -> Source {
        Source::Project {
            path: paths::HostPath::try_new("/proj").unwrap(),
        }
    }

    fn package_source(name: &str) -> Source {
        Source::Package {
            name: name.to_string(),
        }
    }

    fn scripted(answers: Vec<UserChoice>, can_persist: bool) -> InteractivePrompt {
        InteractivePrompt::with_prompter(Box::new(ScriptedPrompter::new(answers)), can_persist)
    }

    /// "Allow permanent" on a project whose path contains glob
    /// metacharacters must store something that means *that* project.
    /// Stored raw, `/tmp/build*` would grant every sibling `build…`
    /// project the right to run code in the user's sessions — an
    /// approval nobody was asked for. Asserted here as well as on the
    /// expander so the escaping cannot be dropped at the call site.
    #[test]
    fn allowing_a_project_with_glob_chars_stores_a_literal_not_a_pattern() {
        let policy = append_hook_pattern(HooksPolicy::empty(), HookBucket::Allow, "/tmp/build*");
        let stored = policy.allow();
        assert_eq!(stored.len(), 1);
        assert_ne!(
            stored[0], "/tmp/build*",
            "the raw path would be read back as a wildcard",
        );

        // What matters is the behaviour after expansion, not the spelling.
        let vars: [sessions::core::primitives::ResolvedVar; 0] = [];
        let fs =
            sessions::core::expansion::expand_policy_pattern(&stored[0], vars.as_slice(), None)
                .expect("the stored entry should expand");
        assert!(
            fs.is_match("/tmp/build*"),
            "should match the project itself"
        );
        assert!(
            !fs.is_match("/tmp/build-someone-elses-project"),
            "should not reach another project",
        );
    }

    // ---- UserChoice option filtering ----

    /// Writable policy file → all six choices offered.
    #[test]
    fn choices_full_set_when_writable() {
        let hook = scripted(vec![], true);
        assert_eq!(hook.choices().len(), 6);
    }

    /// Read-only policy file → only the three "once" / abort choices.
    #[test]
    fn choices_restricted_when_readonly() {
        let hook = scripted(vec![], false);
        assert_eq!(hook.choices(), UserChoice::readonly_only());
    }

    // ---- Per-choice var behavior ----

    /// `AllowOnce` → decision without policy mutation.
    #[test]
    fn var_allow_once_leaves_policy_untouched() {
        let hook = scripted(vec![UserChoice::AllowOnce], true);
        let source = project_source();
        let items = [Unapproved::new("DIAGRAM", &source)];
        let out = hook.on_var_unapproved(VarsPolicy::empty(), &items);
        match out {
            HookResult::Decided {
                decisions,
                updated_policy,
            } => {
                assert_eq!(decisions, vec![ItemDecision::AllowOnce]);
                assert!(updated_policy.is_none(), "policy shouldn't be updated");
            }
            HookResult::Abort => panic!("expected Decided"),
        }
    }

    /// `AllowPermanent` → `UseRule` + policy allow-list gains the name.
    #[test]
    fn var_allow_permanent_appends_to_allow() {
        let hook = scripted(vec![UserChoice::AllowPermanent], true);
        let source = project_source();
        let items = [Unapproved::new("DIAGRAM", &source)];
        let out = hook.on_var_unapproved(VarsPolicy::empty(), &items);
        match out {
            HookResult::Decided {
                decisions,
                updated_policy,
            } => {
                assert_eq!(decisions, vec![ItemDecision::UseRule]);
                let updated = updated_policy.expect("policy should be updated");
                assert_eq!(updated.allow().raw_patterns(), &["DIAGRAM"]);
            }
            HookResult::Abort => panic!("expected Decided"),
        }
    }

    /// `IgnorePermanent` → `UseRule` + policy ignore-list gains the name.
    #[test]
    fn var_ignore_permanent_appends_to_ignore() {
        let hook = scripted(vec![UserChoice::IgnorePermanent], true);
        let source = package_source("go");
        let items = [Unapproved::new("GOCACHE", &source)];
        let out = hook.on_var_unapproved(VarsPolicy::empty(), &items);
        match out {
            HookResult::Decided {
                decisions,
                updated_policy,
            } => {
                assert_eq!(decisions, vec![ItemDecision::UseRule]);
                let updated = updated_policy.expect("policy should be updated");
                assert_eq!(updated.ignore().raw_patterns(), &["GOCACHE"]);
            }
            HookResult::Abort => panic!("expected Decided"),
        }
    }

    /// `Abort` → `HookResult::Abort`, no mutation.
    #[test]
    fn var_abort_returns_hook_abort() {
        let hook = scripted(vec![UserChoice::Abort], true);
        let source = project_source();
        let items = [Unapproved::new("SECRET_KEY", &source)];
        let out = hook.on_var_unapproved(VarsPolicy::empty(), &items);
        assert!(matches!(out, HookResult::Abort), "expected Abort");
    }

    /// `DenyPermanent` → abort *and* policy deny-list gains the name.
    /// We can observe the policy mutation only when it's the last
    /// item and Abort still fires — inspect the hook's policy after.
    #[test]
    fn var_deny_permanent_aborts_but_records_rule() {
        // Two items: first allow-once, second deny-permanent. The
        // hook aborts on the second, but the mutated policy state is
        // observable only via the mutation of the passed-in `policy`.
        // Since Abort discards the policy, we instead assert the
        // apply_var_choice helper mutates directly.
        let mut policy = VarsPolicy::empty();
        let mut touched = false;
        let step = apply_var_choice(
            &mut policy,
            "SECRET",
            UserChoice::DenyPermanent,
            &mut touched,
        );
        assert!(matches!(step, VarStep::Abort));
        assert!(touched, "deny-permanent must set touched");
        assert_eq!(policy.deny().raw_patterns(), &["SECRET"]);
    }

    /// A batch where some items pick `AllowOnce` and one picks
    /// `Abort` returns `HookResult::Abort` immediately — the prompt
    /// loop bails on the first Abort without processing later items.
    #[test]
    fn var_batch_aborts_on_first_abort() {
        let hook = scripted(
            vec![
                UserChoice::AllowOnce,
                UserChoice::Abort,
                UserChoice::AllowOnce,
            ],
            true,
        );
        let source = project_source();
        let items = [
            Unapproved::new("A", &source),
            Unapproved::new("B", &source),
            Unapproved::new("C", &source),
        ];
        let out = hook.on_var_unapproved(VarsPolicy::empty(), &items);
        assert!(matches!(out, HookResult::Abort));
    }

    // ---- Per-choice patch behavior ----

    /// `AllowPermanent` for a patch appends the exact absolute path
    /// to the policy's allow list.
    #[test]
    fn patch_allow_permanent_appends_absolute_path() {
        let hook = scripted(vec![UserChoice::AllowPermanent], true);
        let source = package_source("go");
        let path = camino::Utf8Path::new("/home/u/.config/go/env");
        let items = [Unapproved::new(path, &source)];
        let out = hook.on_patch_unapproved(PatchesPolicy::empty(), &items);
        match out {
            HookResult::Decided {
                decisions,
                updated_policy,
            } => {
                assert_eq!(decisions, vec![ItemDecision::UseRule]);
                let updated = updated_policy.expect("policy should be updated");
                assert_eq!(updated.allow(), &["/home/u/.config/go/env"]);
            }
            HookResult::Abort => panic!("expected Decided"),
        }
    }

    // ---- NoPromptHook ----

    /// `NoPromptHook` fake-approves every unapproved var
    /// (so `handle_response` keeps going and the patch hook fires
    /// too — otherwise the operator's `--no-prompt` snippet would
    /// only list vars) and records them in the summary. The caller
    /// (cmd_activate) is responsible for checking `summary.count()`
    /// and aborting before actually shipping the verdict.
    #[test]
    fn no_prompt_hook_fake_approves_and_records_var() {
        let hook = NoPromptHook::new();
        let source = project_source();
        let items = [
            Unapproved::new("DIAGRAM", &source),
            Unapproved::new("GOCACHE", &source),
        ];
        let out = hook.on_var_unapproved(VarsPolicy::empty(), &items);
        match out {
            HookResult::Decided { decisions, .. } => {
                assert_eq!(decisions.len(), 2);
                assert!(decisions.iter().all(|d| *d == ItemDecision::AllowOnce));
            }
            HookResult::Abort => panic!("expected fake-approve Decided, got Abort"),
        }
        let summary = hook.into_summary();
        assert_eq!(summary.count(), 2);
        assert_eq!(summary.vars, vec!["DIAGRAM", "GOCACHE"]);
    }

    /// `NoPromptHook` collects both vars and patches when both hooks
    /// fire — the `--no-prompt` snippet has to list every item the
    /// operator needs to approve, not just whichever hook fired
    /// first. Duplicates across calls dedupe so the snippet doesn't
    /// render `allow = ["X", "X"]`.
    #[test]
    fn no_prompt_hook_collects_across_var_and_patch_hooks_and_dedupes() {
        let hook = NoPromptHook::new();
        let source = project_source();

        let vars_a = [
            Unapproved::new("DIAGRAM", &source),
            Unapproved::new("GOCACHE", &source),
        ];
        let _ = hook.on_var_unapproved(VarsPolicy::empty(), &vars_a);

        // A second var hook batch: `DIAGRAM` repeats (a second
        // package wanted it too) and `LOG_LEVEL` is new.
        let vars_b = [
            Unapproved::new("DIAGRAM", &source),
            Unapproved::new("LOG_LEVEL", &source),
        ];
        let _ = hook.on_var_unapproved(VarsPolicy::empty(), &vars_b);

        let path = camino::Utf8Path::new("/etc/foo");
        let patch_items = [Unapproved::new(path, &source)];
        let _ =
            hook.on_patch_unapproved(sessions::core::policy::PatchesPolicy::empty(), &patch_items);

        let summary = hook.into_summary();
        assert_eq!(summary.vars, vec!["DIAGRAM", "GOCACHE", "LOG_LEVEL"]);
        assert_eq!(summary.patches, vec!["/etc/foo"]);
    }

    /// `--no-prompt` records the projects whose hooks would need
    /// approval and renders them into the `[hooks]` section of the
    /// pasteable snippet.
    ///
    /// Without this the snippet would tell an operator how to unblock
    /// the vars and patches but stay silent about the hooks, so the
    /// activation would fail again on the next run for a reason the
    /// error never mentioned.
    #[test]
    fn no_prompt_hook_collects_projects_and_renders_hooks_section() {
        let hook = NoPromptHook::new();
        let source = project_source();
        let root = camino::Utf8Path::new("/repo");

        let items = [Unapproved::new(root, &source)];
        let _ = hook.on_hook_unapproved(HooksPolicy::empty(), &items);
        // A second batch naming the same project must not duplicate.
        let _ = hook.on_hook_unapproved(HooksPolicy::empty(), &items);

        let summary = hook.into_summary();
        assert_eq!(summary.hooks, vec!["/repo"]);
        assert_eq!(summary.count(), 1);

        let snippet = summary.as_toml_snippet();
        assert!(snippet.contains("[hooks]"), "got: {snippet}");
        assert!(snippet.contains("\"/repo\""), "got: {snippet}");
        // The snippet must parse — it is meant to be pasted verbatim.
        let parsed: sessions::core::policy::UserPolicy =
            toml::from_str(&snippet).expect("snippet must be valid user_policy.toml");
        assert_eq!(parsed.hooks().allow(), &["/repo".to_string()]);
    }

    /// A project the user permanently allows lands in the hooks
    /// policy's `allow` list, so the next activation of that project
    /// runs its hooks without asking again.
    #[test]
    fn allow_permanent_appends_project_to_hooks_allow() {
        let mut policy = HooksPolicy::empty();
        let mut touched = false;
        let step = apply_hook_choice(
            &mut policy,
            "/repo",
            UserChoice::AllowPermanent,
            &mut touched,
        );
        assert!(matches!(step, HookStep::Decision(ItemDecision::UseRule)));
        assert!(touched);
        assert_eq!(policy.allow(), &["/repo".to_string()]);
        assert!(policy.deny().is_empty());
    }

    /// A permanent denial records the rule *and* aborts, matching the
    /// patch domain: the user is saying "never" and "not now" at once.
    #[test]
    fn deny_permanent_records_rule_and_aborts() {
        let mut policy = HooksPolicy::empty();
        let mut touched = false;
        let step = apply_hook_choice(
            &mut policy,
            "/repo",
            UserChoice::DenyPermanent,
            &mut touched,
        );
        assert!(matches!(step, HookStep::Abort));
        assert!(touched);
        assert_eq!(policy.deny(), &["/repo".to_string()]);
    }

    /// The TOML snippet builder groups by domain, quotes correctly,
    /// and omits empty sections.
    #[test]
    fn no_prompt_summary_toml_snippet_groups_and_quotes() {
        let mut summary = UnapprovedSummary::default();
        summary.vars.push("DIAGRAM".into());
        summary.vars.push("GOCACHE".into());
        summary.patches.push("/etc/foo".into());
        let s = summary.as_toml_snippet();
        let expected = "\
[vars]
allow = [\"DIAGRAM\", \"GOCACHE\"]

[patches]
allow = [\"/etc/foo\"]
";
        assert_eq!(s, expected);
    }

    /// Empty summary produces empty snippet — a caller can join it
    /// unconditionally without emitting spurious sections.
    #[test]
    fn no_prompt_summary_empty_yields_empty_snippet() {
        let summary = UnapprovedSummary::default();
        assert_eq!(summary.as_toml_snippet(), "");
    }

    // ---- Persistence round-trip ----

    /// `save_user_policy` writes a valid TOML that round-trips back
    /// to the same [`UserPolicy`] via [`read_user_policy_file`].
    #[test]
    fn save_user_policy_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("user_policy.toml");
        let policy = UserPolicy::empty().with_vars(
            VarsPolicy::empty()
                .try_with_allow(["DIAGRAM", "GOCACHE"])
                .unwrap(),
        );
        save_user_policy(&path, &policy).unwrap();
        let round =
            sessions::core::policy::read_user_policy_file(&path).expect("re-read must succeed");
        assert_eq!(round, policy);
    }

    /// A pre-existing file gets copied to `.bak` before overwrite.
    #[test]
    fn save_user_policy_backs_up_existing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("user_policy.toml");
        std::fs::write(&path, "# old contents\n").unwrap();
        let policy = UserPolicy::empty();
        save_user_policy(&path, &policy).unwrap();
        let bak = tmp.path().join("user_policy.toml.bak");
        assert!(bak.exists(), ".bak must be created");
        let bak_contents = std::fs::read_to_string(&bak).unwrap();
        assert_eq!(bak_contents, "# old contents\n");
    }

    /// Comments and unrelated formatting survive a policy save.
    /// Guards the toml_edit-based path against a regression back to
    /// the plain `toml::to_string` reserialization that lost every
    /// comment.
    #[test]
    fn save_user_policy_preserves_comments_and_formatting() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("user_policy.toml");
        // Existing file has a heading comment, an inline comment,
        // and a rule the caller isn't modifying.
        let original = "\
# User policy for minimal
# Edit by hand or via `min session activate`.

[vars]
# Approved env vars from projects.
allow = [\"DIAGRAM\"]
";
        std::fs::write(&path, original).unwrap();

        // Add `GOCACHE` to the allow list via a save call.
        let policy = UserPolicy::empty().with_vars(
            VarsPolicy::empty()
                .try_with_allow(["DIAGRAM", "GOCACHE"])
                .unwrap(),
        );
        save_user_policy(&path, &policy).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("# User policy for minimal"),
            "top-of-file comment must survive, got: {after}"
        );
        assert!(
            after.contains("# Approved env vars from projects."),
            "in-section comment must survive, got: {after}"
        );
        assert!(
            after.contains("GOCACHE"),
            "new rule must be persisted, got: {after}"
        );
        assert!(
            after.contains("DIAGRAM"),
            "existing rule must be preserved, got: {after}"
        );
    }

    /// An empty rule list is omitted rather than written as `[]`.
    /// Matches the serde `skip_serializing_if = "Vec::is_empty"`
    /// behavior — a policy with no denies shouldn't produce
    /// `deny = []` noise in the saved file.
    #[test]
    fn save_user_policy_omits_empty_arrays() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("user_policy.toml");
        let policy =
            UserPolicy::empty().with_vars(VarsPolicy::empty().try_with_allow(["FOO"]).unwrap());
        save_user_policy(&path, &policy).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("allow"), "expected allow, got: {after}");
        assert!(!after.contains("deny"), "expected no deny, got: {after}");
        assert!(
            !after.contains("ignore"),
            "expected no ignore, got: {after}"
        );
        assert!(
            !after.contains("[patches]"),
            "empty [patches] section should be omitted, got: {after}",
        );
    }

    // ---- is_writable ----

    /// Non-existent file with writable parent → we can create it.
    #[test]
    fn is_writable_missing_file_writable_parent_returns_true() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.toml");
        assert!(is_writable(&path));
    }

    /// A file that exists and is writable → true.
    #[test]
    fn is_writable_existing_writable_file_returns_true() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("policy.toml");
        std::fs::write(&path, "").unwrap();
        assert!(is_writable(&path));
    }

    /// A file with the read-only bit set → false.
    #[test]
    fn is_writable_readonly_file_returns_false() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("policy.toml");
        std::fs::write(&path, "").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(!is_writable(&path));
    }
}
