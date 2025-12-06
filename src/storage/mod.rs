//! Storage module for VM state and data management
//!
//! This module handles persistent storage of VM metadata, disk images,
//! and rootfs directories.

mod state;
mod paths;

pub use state::{VmState, VmStatus, VmStore};
pub use paths::VmmPaths;
