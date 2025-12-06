//! VM state management

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use super::paths::VmmPaths;

/// Status of a VM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmStatus {
    /// VM is being created
    Creating,
    /// VM is created but not running
    Stopped,
    /// VM is currently running
    Running,
    /// VM failed to start or crashed
    Failed,
}

impl std::fmt::Display for VmStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmStatus::Creating => write!(f, "creating"),
            VmStatus::Stopped => write!(f, "stopped"),
            VmStatus::Running => write!(f, "running"),
            VmStatus::Failed => write!(f, "failed"),
        }
    }
}

/// State of a single VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    /// Unique identifier for the VM
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Source image (e.g., "ubuntu:latest")
    pub image: String,
    /// Detected distro type
    pub distro: String,
    /// Current status
    pub status: VmStatus,
    /// Number of vCPUs
    pub vcpus: u8,
    /// RAM in MiB
    pub ram_mib: u32,
    /// Process ID if running
    pub pid: Option<u32>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last started timestamp
    pub started_at: Option<DateTime<Utc>>,
}

impl VmState {
    /// Create a new VM state
    pub fn new(id: String, name: String, image: String, distro: String) -> Self {
        Self {
            id,
            name,
            image,
            distro,
            status: VmStatus::Creating,
            vcpus: 2,
            ram_mib: 2048,
            pid: None,
            created_at: Utc::now(),
            started_at: None,
        }
    }

    /// Generate a short ID (first 12 characters)
    pub fn short_id(&self) -> &str {
        &self.id[..12.min(self.id.len())]
    }
}

/// Global store for all VM states
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VmStore {
    pub vms: HashMap<String, VmState>,
}

impl VmStore {
    /// Load the store from disk
    pub fn load(paths: &VmmPaths) -> Result<Self> {
        let state_file = paths.global_state_file();
        if state_file.exists() {
            let contents = std::fs::read_to_string(&state_file)
                .context("Failed to read state file")?;
            serde_json::from_str(&contents).context("Failed to parse state file")
        } else {
            Ok(Self::default())
        }
    }

    /// Save the store to disk
    pub fn save(&self, paths: &VmmPaths) -> Result<()> {
        let state_file = paths.global_state_file();
        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize state")?;
        std::fs::write(&state_file, contents).context("Failed to write state file")
    }

    /// Add a VM to the store
    pub fn add(&mut self, vm: VmState) {
        self.vms.insert(vm.id.clone(), vm);
    }

    /// Get a VM by ID or name
    pub fn get(&self, id_or_name: &str) -> Option<&VmState> {
        // Try exact ID match first
        if let Some(vm) = self.vms.get(id_or_name) {
            return Some(vm);
        }

        // Try short ID match
        for (id, vm) in &self.vms {
            if id.starts_with(id_or_name) {
                return Some(vm);
            }
        }

        // Try name match
        for vm in self.vms.values() {
            if vm.name == id_or_name {
                return Some(vm);
            }
        }

        None
    }

    /// Get a mutable VM by ID or name
    pub fn get_mut(&mut self, id_or_name: &str) -> Option<&mut VmState> {
        // Try exact ID match first
        if self.vms.contains_key(id_or_name) {
            return self.vms.get_mut(id_or_name);
        }

        // Find by short ID or name
        let id = self.vms.iter().find_map(|(id, vm)| {
            if id.starts_with(id_or_name) || vm.name == id_or_name {
                Some(id.clone())
            } else {
                None
            }
        });

        id.and_then(|id| self.vms.get_mut(&id))
    }

    /// Remove a VM from the store
    pub fn remove(&mut self, id_or_name: &str) -> Option<VmState> {
        // Try exact ID match first
        if self.vms.contains_key(id_or_name) {
            return self.vms.remove(id_or_name);
        }

        // Find by short ID or name
        let id = self.vms.iter().find_map(|(id, vm)| {
            if id.starts_with(id_or_name) || vm.name == id_or_name {
                Some(id.clone())
            } else {
                None
            }
        });

        id.and_then(|id| self.vms.remove(&id))
    }

    /// List all VMs
    pub fn list(&self) -> Vec<&VmState> {
        let mut vms: Vec<_> = self.vms.values().collect();
        vms.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        vms
    }

    /// Update VM status based on running processes
    pub fn refresh_status(&mut self) {
        for vm in self.vms.values_mut() {
            if vm.status == VmStatus::Running {
                if let Some(pid) = vm.pid {
                    // Check if process is still running
                    let is_running = unsafe { libc::kill(pid as i32, 0) == 0 };
                    if !is_running {
                        vm.status = VmStatus::Stopped;
                        vm.pid = None;
                    }
                } else {
                    vm.status = VmStatus::Stopped;
                }
            }
        }
    }
}
