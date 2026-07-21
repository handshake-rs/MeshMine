//! Authenticated local Core-to-operator assignment and capture link.
//!
//! The link deliberately uses a bounded Unix-domain transport. The transport
//! authenticates both process credentials and pinned Ed25519 identities, while
//! every authority-bearing protocol object retains its own domain-separated
//! signature. The crate does not create mining consensus or weaken any Core-v2
//! validation boundary.

mod admission;
mod bundle;
mod client;
mod protocol;
mod spool;
mod transport;

pub use admission::*;
pub use bundle::*;
pub use client::*;
pub use protocol::*;
pub use spool::*;
pub use transport::*;

#[cfg(test)]
mod tests;
