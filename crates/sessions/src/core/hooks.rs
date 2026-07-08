//! Application-supplied callbacks for items the policy couldn't decide.
//!
//! The gate hands the application a batch of [`Unapproved`] items
//! per domain and waits for a [`HookResult`] with one [`ItemDecision`]
//! per item (and, optionally, a mutated policy snapshot).

use crate::core::decision::ItemDecision;
use crate::core::policy::{PatchPolicy, VarsPolicy};
use crate::core::source::Source;

/// One item the policy could not decide, borrowed from the gate
/// loop for the duration of the hook call.
#[derive(Clone, Debug)]
pub struct Unapproved<'a, T: ?Sized> {
    pub(crate) item: &'a T,
    pub(crate) source: &'a Source,
}

impl<'a, T: ?Sized> Unapproved<'a, T> {
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
/// (`VarsPolicy` / `PatchPolicy`); they cannot mutate the gate's
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
        policy: PatchPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchPolicy>;
}
