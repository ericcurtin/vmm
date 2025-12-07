//! CLI interface module

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vmm")]
#[command(about = "A Docker-like experience for VMs using libkrun")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

/// Get the default number of CPUs (all available on host, capped at 4 for stability)
pub fn default_cpus() -> u8 {
    let available = std::thread::available_parallelism()
        .map(|n| n.get() as u8)
        .unwrap_or(2);
    // Cap at 4 for stability with libkrun
    available.min(4)
}

/// Get the default memory in MiB (highest power of 2 less than available, capped at 4GB)
pub fn default_memory_mib() -> u32 {
    use sysinfo::System;

    let sys = System::new_all();
    let total_mem_bytes = sys.total_memory();
    let total_mem_mib = (total_mem_bytes / (1024 * 1024)) as u32;

    // Find highest power of 2 less than total memory
    // Start from 2^12 (4096 MiB = 4 GiB) - capped for stability with libkrun
    let mut power_of_2: u32 = 4096;
    while power_of_2 >= total_mem_mib && power_of_2 > 512 {
        power_of_2 /= 2;
    }

    power_of_2
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a VM from a container image
    Run {
        /// The container image to run (e.g., ubuntu, fedora)
        image: String,

        /// Number of vCPUs (default: all available)
        #[arg(long)]
        cpus: Option<u8>,

        /// Memory in MiB (default: highest power of 2 less than host memory)
        #[arg(long)]
        memory: Option<u32>,

        /// Name for the VM
        #[arg(long)]
        name: Option<String>,
    },

    /// List all VMs
    #[command(visible_alias = "ps")]
    Images,

    /// List all VMs (alias for images)
    Ls,

    /// Stop a running VM
    Stop {
        /// VM ID or name
        vm: String,
    },

    /// Remove a VM
    Rm {
        /// VM ID or name
        vm: String,

        /// Force removal even if running
        #[arg(short, long)]
        force: bool,
    },

    /// Start a stopped VM
    Start {
        /// VM ID or name
        vm: String,
    },

    /// Attach to a running VM
    Attach {
        /// VM ID or name
        vm: String,
    },

    /// Show VM details
    Inspect {
        /// VM ID or name
        vm: String,
    },

    /// Pull a container image (without running)
    Pull {
        /// The container image to pull
        image: String,
    },
}
