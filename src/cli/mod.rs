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

#[derive(Subcommand)]
pub enum Commands {
    /// Run a VM from a container image
    Run {
        /// The container image to run (e.g., ubuntu, fedora:41)
        image: String,

        /// Number of vCPUs
        #[arg(long, default_value = "2")]
        cpus: u8,

        /// Memory in MiB
        #[arg(long, default_value = "2048")]
        memory: u32,

        /// Name for the VM
        #[arg(long)]
        name: Option<String>,

        /// Command to run in the VM (if not specified, starts interactive shell)
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
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
