//! The mirror daemon (spec MIR): one copy per laptop of the cache objects and
//! package repositories its clients fetch.
//!
//! The daemon answers HTTP/1.1 on two Unix sockets. The host socket takes
//! every request; the door socket, which each VM host daemon connects its
//! guest's vsock door to, takes reads alone (MIR-080). Cache objects live
//! under the origin the client asked for (O1), repository copies under their
//! slug (O2), and both fill on the first request that names them.

pub mod daemon;
pub mod git;
pub mod origin;
pub mod server;
pub mod state;
pub mod status;
pub mod store;

pub use daemon::run;
