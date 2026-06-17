//! Policy decision types.
//!
//! [`Decision<T>`] is the final verdict for a single item; [`CheckOutcome<T>`]
//! is what a policy's `check` returns (decided vs. needs approval); and
//! [`ItemDecision`] is the application-supplied verdict returned by a
//! [`PolicyHooks`](crate::core::hooks::PolicyHooks) callback for each
//! item the policy couldn't decide.

/// What the policy decided about a single item.
///
/// `Ignored` carries no payload — the caller silently drops the item.
/// `Allowed` and `Denied` carry the item through so callers can collect
/// it (or, in the case of `Denied`, name it in the error).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Decision<T> {
    /// The item passes the policy and should be included.
    Allowed(T),
    /// The item matches an `ignore` rule and should be silently dropped.
    Ignored,
    /// The item is explicitly forbidden; session construction aborts.
    Denied(T),
}

/// The outcome of a single policy `check`.
///
/// `NeedsApproval` hands the item back so the resolve loop can prompt
/// for it via a [`PolicyHooks`](crate::core::hooks::PolicyHooks)
/// callback and re-check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CheckOutcome<T> {
    /// The policy reached a verdict on its own.
    Decided(Decision<T>),
    /// No rule matched; the item must be referred to a
    /// [`PolicyHooks`](crate::core::hooks::PolicyHooks) callback for
    /// an application-level decision.
    NeedsApproval(T),
}

/// One application-supplied decision per `Unapproved` item, returned by
/// a [`PolicyHooks`](crate::core::hooks::PolicyHooks) callback in the
/// same order the items were given.
///
/// There is no per-item deny: rejecting a single item is functionally
/// identical to aborting the whole composition (denial of any item
/// terminates), so use [`HookResult::Abort`](crate::core::hooks::HookResult::Abort)
/// to reject. Reserve `AllowOnce` / `UseRule` for items that should
/// survive or be re-checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ItemDecision {
    /// Approve this item without recording a rule.
    AllowOnce,
    /// Re-check against the (possibly mutated) policy.
    UseRule,
}
