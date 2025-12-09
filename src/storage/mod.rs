//! Storage module for VM state and data management
//!
//! This module handles persistent storage of VM metadata, disk images,
//! and rootfs directories.

mod paths;
mod state;

pub use paths::VmmPaths;
pub use state::{VmState, VmStatus, VmStore};
