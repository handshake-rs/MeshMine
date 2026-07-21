//! Portable mining work coordination for MeshMine.
//!
//! This crate deliberately contains no CUDA, ROCm, NEON, AVX, or ASIC-
//! specific hashing implementation. It turns a signed MeshMine assignment
//! into a smaller durable local lease, delivers that lease through a backend,
//! verifies captures with the scalar `meshmine-hns` oracle, and acknowledges
//! work only after a downstream consumer reports durable admission.

mod backend;
mod capabilities;
mod coordinator;
mod lease;
mod planner;
mod record;
mod target;

pub use backend::*;
pub use capabilities::*;
pub use coordinator::*;
pub use lease::*;
pub use planner::*;
pub use record::*;
pub use target::*;

#[cfg(test)]
mod tests;
