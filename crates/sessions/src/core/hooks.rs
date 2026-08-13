//! Application-supplied callbacks for items the policy couldn't decide.
//!
//! The gate hands the application a batch of [`Unapproved`] items
//! per domain and waits for a [`HookResult`] with one [`ItemDecision`]
//! per item (and, optionally, a mutated policy snapshot).

use crate::core::decision::ItemDecision;
use crate::core::policy::{HooksPolicy, PatchesPolicy, VarsPolicy};
use crate::core::source::Source;

/// One item the policy could not decide, borrowed from the gate
/// loop for the duration of the hook call.
#[derive(Clone, Debug)]
pub struct Unapproved<'a, T: ?Sized> {
    pub(crate) item: &'a T,
    pub(crate) source: &'a Source,
}

impl<'a, T: ?Sized> Unapproved<'a, T> {
    /// Construct an [`Unapproved`] from a borrow. Intended for
    /// callers that own their own item/source pair (e.g.
    /// [`PolicyHooks`] implementations under test). The gate loop
    /// itself constructs [`Unapproved`] via a struct literal from
    /// its own private types.
    #[must_use]
    pub fn new(item: &'a T, source: &'a Source) -> Self {
        Self { item, source }
    }

    /// The item the policy couldn't decide on (e.g. a variable name or
    /// patch source path).
    #[must_use]
    pub fn item(&self) -> &'a T {
        self.item
    }

    /// The [`Source`] that contributed this item — useful for prompts
    /// like "project `~/foo` wants to set `AWS_KEY`."
    #[must_use]
    pub fn source(&self) -> &'a Source {
        self.source
    }
}

/// The hook's response to the batch of unapproved items.
///
/// Hooks **cannot** mutate the policy directly. If the application
/// updates the policy in response to the prompt, it returns the updated
/// copy in `updated_policy`. `None` means "no rule changes." The gate
/// installs `updated_policy` (if `Some`) before re-checking any
/// `UseRule` decisions in this batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookResult<P> {
    /// Per-item decisions, indexed parallel to the input slice, plus
    /// an optional updated policy snapshot.
    Decided {
        decisions: Vec<ItemDecision>,
        updated_policy: Option<P>,
    },
    /// User chose to abort session construction.
    Abort,
}

impl<P> HookResult<P> {
    /// Construct a [`Decided`](Self::Decided) result that leaves the
    /// policy unchanged.
    #[must_use]
    pub fn decided(decisions: Vec<ItemDecision>) -> Self {
        Self::Decided {
            decisions,
            updated_policy: None,
        }
    }

    /// Construct a [`Decided`](Self::Decided) result that installs a
    /// new policy snapshot.
    #[must_use]
    pub fn decided_with_policy(decisions: Vec<ItemDecision>, updated_policy: P) -> Self {
        Self::Decided {
            decisions,
            updated_policy: Some(updated_policy),
        }
    }

    /// Construct an [`Abort`](Self::Abort) result.
    #[must_use]
    pub fn abort() -> Self {
        Self::Abort
    }
}

/// Application-supplied hooks for handling items the policy couldn't
/// decide on its own.
///
/// Hooks receive an owned copy of the *narrow* domain policy
/// (`VarsPolicy` / `PatchesPolicy`); they cannot mutate the gate's
/// state directly. To add rules, return a modified policy snapshot in
/// [`HookResult::Decided::updated_policy`] — wider mutations to the
/// full [`UserPolicy`](crate::core::policy::UserPolicy) are not
/// exposed here.
///
/// # `~` in returned patch policies
///
/// Patch-policy patterns are stored verbatim and round-trip losslessly.
/// When a hook adds (or modifies) a patch-policy rule with a leading
/// `~`, return it in `~`-form — the gate re-expands the policy
/// internally for matching, while the returned policy keeps the raw
/// form so the caller can persist it. Do **not** expand `~` inside the
/// hook; double-expansion will produce wrong matches.
///
/// Vars policies have no analogous `~`-expansion concern: variable
/// names are not paths, so the home directory is not relevant on the
/// vars side.
pub trait PolicyHooks {
    fn on_var_unapproved(
        &self,
        policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy>;

    fn on_patch_unapproved(
        &self,
        policy: PatchesPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy>;

    /// Decide whether a project's lifecycle hooks may run.
    ///
    /// Each item's borrowed value is the **project root path**, not a
    /// script — one entry per project awaiting a decision, deduplicated
    /// by the gate, because a project's hooks are allowed or refused as
    /// a set rather than one script at a time. Approving here grants
    /// arbitrary code execution inside the session, so an implementation
    /// that prompts should say so plainly.
    ///
    /// The `~`-form guidance for patch policies applies here too:
    /// return added rules in `~`-form and let the gate expand them.
    ///
    /// # Default
    ///
    /// Aborts. Approving a hook grants arbitrary code execution, so an
    /// implementation that hasn't considered this domain must not be
    /// able to grant it by omission. Aborting fails closed *and*
    /// loudly: the activation stops with a visible error rather than
    /// quietly composing a session whose hooks were dropped. Every
    /// implementation that can actually ask the user should override
    /// this; the default exists for test doubles and for
    /// var/patch-only consumers.
    fn on_hook_unapproved(
        &self,
        _policy: HooksPolicy,
        _items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        HookResult::Abort
    }
}
