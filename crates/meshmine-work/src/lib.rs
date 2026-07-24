//! Portable mining work coordination for MeshMine.
//!
//! It turns a signed MeshMine assignment into a smaller durable local lease,
//! delivers that lease through a backend, verifies captures with the scalar
//! `meshmine-hns` oracle, and acknowledges work only after a downstream
//! consumer reports durable admission. The native CPU backend is implemented
//! here alongside the headless Vulkan GPU backend; stock-ASIC transports use
//! the gateway while preserving the same capture-verification boundary.

mod backend;
mod capabilities;
mod coordinator;
mod lease;
mod planner;
mod record;
mod target;
mod vulkan;

pub use backend::*;
pub use capabilities::*;
pub use coordinator::*;
pub use lease::*;
pub use planner::*;
pub use record::*;
pub use target::*;
pub use vulkan::*;

#[cfg(test)]
mod tests;
