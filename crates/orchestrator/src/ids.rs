//! Identifiers shared by the `state` and `traits` modules.
//!
//! This is a leaf module: it imports neither `state` nor `traits`.

use generational_arena::Index;

/// A reference to a [`Deliverable`](crate::Deliverable) within
/// [`State`](crate::State).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverableRef(Index);

impl DeliverableRef {
    /// Wraps an arena index. Only `state` builds one, from its own arena.
    pub(crate) fn new(idx: Index) -> Self {
        Self(idx)
    }

    /// Returns the arena index this reference wraps.
    pub(crate) fn index(self) -> Index {
        self.0
    }

    // Returns the inner index. DO NOT USE unless you know what you are doing.
    pub(crate) fn inner_idx(&self) -> usize {
        self.0.into_raw_parts().0
    }
}
