//! Upstream connections, kept per box (BEP-077).
//!
//! The proxy reuses an idle upstream connection only for the box that opened
//! it. A connection is never shared across boxes. If it were, one box's
//! request could reach the upstream on a connection that another box's
//! framing left in an unknown state.
//!
//! [`UpstreamPool::checkout`] returns an [`Upstream`] that carries the box id
//! and the authority it is for. [`UpstreamPool::checkin`] takes the
//! connection back under that same key. No call puts a connection under a
//! key that it did not come from.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

/// The key of an idle list: one box and one upstream authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamKey {
    /// The box the connection carries requests for.
    pub box_id: String,
    /// The upstream host name, in lowercase.
    pub host: String,
    /// The upstream port.
    pub port: u16,
}

/// An upstream connection, held for one box.
#[derive(Debug)]
pub struct Upstream<C> {
    key: UpstreamKey,
    /// The connection itself.
    pub conn: C,
}

impl<C> Upstream<C> {
    /// The box this connection carries requests for.
    #[must_use]
    pub fn box_id(&self) -> &str {
        &self.key.box_id
    }

    /// The key this connection is held under.
    #[must_use]
    pub fn key(&self) -> &UpstreamKey {
        &self.key
    }
}

/// The idle upstream connections, keyed per box and authority.
#[derive(Debug)]
pub struct UpstreamPool<C> {
    idle: Mutex<HashMap<UpstreamKey, Vec<C>>>,
}

impl<C> Default for UpstreamPool<C> {
    fn default() -> Self {
        Self {
            idle: Mutex::new(HashMap::new()),
        }
    }
}

impl<C> UpstreamPool<C> {
    /// An empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An idle connection of `box_id` to `host:port`, or a new one from
    /// `connect` when the box has none.
    ///
    /// # Errors
    ///
    /// Returns the error of `connect`.
    pub fn checkout(
        &self,
        box_id: &str,
        host: &str,
        port: u16,
        connect: impl FnOnce() -> io::Result<C>,
    ) -> io::Result<Upstream<C>> {
        let key = UpstreamKey {
            box_id: box_id.to_owned(),
            host: host.to_ascii_lowercase(),
            port,
        };
        let reused = self.lock().get_mut(&key).and_then(Vec::pop);
        let conn = match reused {
            Some(conn) => conn,
            None => connect()?,
        };
        Ok(Upstream { key, conn })
    }

    /// Put a connection back as idle, under the box and authority it came
    /// from. The caller gives back only a connection whose last response
    /// ended cleanly. A connection the proxy closed is dropped instead.
    pub fn checkin(&self, upstream: Upstream<C>) {
        self.lock()
            .entry(upstream.key)
            .or_default()
            .push(upstream.conn);
    }

    /// Drop every idle connection of `box_id`, for example when the box
    /// ends.
    pub fn drop_box(&self, box_id: &str) {
        self.lock().retain(|key, _| key.box_id != box_id);
    }

    /// The number of idle connections of `box_id`.
    #[must_use]
    pub fn idle_count(&self, box_id: &str) -> usize {
        self.lock()
            .iter()
            .filter(|(key, _)| key.box_id == box_id)
            .map(|(_, conns)| conns.len())
            .sum()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<UpstreamKey, Vec<C>>> {
        // A panic while the lock is held leaves only a list of idle
        // connections, which stays consistent.
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    // BEP-077: each box's requests ride upstream connections no other box
    // uses.
    #[test]
    fn upstream_connections_never_shared_across_boxes() {
        let pool = UpstreamPool::new();
        let next = Cell::new(0u32);
        let connect = || {
            next.set(next.get() + 1);
            Ok(next.get())
        };

        let a = pool
            .checkout("box-a", "api.github.com", 443, connect)
            .unwrap();
        assert_eq!(a.box_id(), "box-a");
        let a_conn = a.conn;
        pool.checkin(a);
        assert_eq!(pool.idle_count("box-a"), 1);

        // Box B has no idle connection of its own, so it gets a new one,
        // never box A's.
        let b = pool
            .checkout("box-b", "api.github.com", 443, connect)
            .unwrap();
        assert_ne!(b.conn, a_conn);
        assert_eq!(pool.idle_count("box-a"), 1, "box A's idle connection stays");

        // Box B's connection goes back to box B only.
        let b_conn = b.conn;
        pool.checkin(b);
        let a_again = pool
            .checkout("box-a", "API.github.com", 443, connect)
            .unwrap();
        assert_eq!(a_again.conn, a_conn, "box A reuses its own connection");
        let b_again = pool
            .checkout("box-b", "api.github.com", 443, connect)
            .unwrap();
        assert_eq!(b_again.conn, b_conn, "box B reuses its own connection");

        // Another authority is another connection, for the same box.
        let other = pool.checkout("box-a", "github.com", 443, connect).unwrap();
        assert_ne!(other.conn, a_conn);

        pool.checkin(a_again);
        pool.checkin(b_again);
        pool.drop_box("box-a");
        assert_eq!(pool.idle_count("box-a"), 0);
        assert_eq!(pool.idle_count("box-b"), 1);
        assert_eq!(next.get(), 3);
    }
}
