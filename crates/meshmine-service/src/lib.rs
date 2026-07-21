//! Continuous operator-service foundations for MeshMine.
//!
//! This crate composes already-authorized gateway work into a supervised local
//! service. It does not create assignments, manufacture Core share context, or
//! grant mining authority. Its capture reconciler is deliberately ACK-only:
//! gateway payloads are compacted only when an immutable downstream receipt is
//! already durable.

mod dashboard;
mod journal;
mod receipt;
mod schema;
mod supervisor;

pub use dashboard::*;
pub use journal::*;
pub use receipt::*;
pub use schema::*;
pub use supervisor::*;
