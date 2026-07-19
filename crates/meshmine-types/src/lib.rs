//! MM-0001 Core v2 protocol objects.
//!
//! IDs are acyclic BLAKE2b-256 commitments over unsigned canonical bodies.
//! Signature fields are always encoded for transport and always excluded from
//! object IDs.

mod common;
mod objects;
mod state;

pub use common::*;
pub use objects::*;
pub use state::*;

#[cfg(test)]
mod tests;
