# vmm

A Docker-like experience for VMs using [libkrun](https://github.com/containers/libkrun).

vmm lets you run container images as lightweight virtual machines on macOS, providing full Linux VM isolation with the familiar Docker workflow.

## Features

- **Docker-like CLI** - Familiar commands: `run`, `stop`, `rm`, `ls`, `pull`
- **Container image support** - Run any OCI container image as a VM
- **Short names** - Use `fedora`, `ubuntu`, `centos` instead of full registry paths
- **Auto-login** - VMs boot directly to a shell as your user
- **Home directory sharing** - Your macOS home directory is mounted in the VM via virtiofs

## Requirements

- macOS (Apple Silicon or Intel)
- Docker Desktop (for pulling container images)
- Rust toolchain (for building from source)

## Installation

```bash
git clone https://github.com/ecurtin/vmm.git
cd vmm
make release
```

This builds and signs the binary with the required Hypervisor.framework entitlement.

The binary will be at `./target/release/vmm`.

> **Note**: On macOS, the binary must be signed with the `com.apple.security.hypervisor` entitlement to use the Hypervisor.framework. The Makefile handles this automatically. If you build with `cargo build` directly, run `make sign` afterwards.

## Quick Start

```bash
# Run a Fedora VM
vmm run fedora

# Run Ubuntu with custom resources
vmm run ubuntu --cpus 4 --memory 4096

# List VMs
vmm ls

# Stop a VM
vmm stop <vm-id>

# Remove a VM
vmm rm <vm-id>
```

## Commands

| Command | Description |
|---------|-------------|
| `run <image>` | Run a VM from a container image |
| `ls` / `images` | List all VMs |
| `stop <vm>` | Stop a running VM |
| `start <vm>` | Start a stopped VM |
| `rm <vm>` | Remove a VM |
| `attach <vm>` | Attach to a running VM |
| `inspect <vm>` | Show VM details as JSON |
| `pull <image>` | Pull a container image without running |

## Options

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

### Run Options

| Option | Description |
|--------|-------------|
| `--cpus <N>` | Number of vCPUs (default: all available) |
| `--memory <MiB>` | Memory in MiB (default: highest power of 2 less than host memory) |
| `--name <NAME>` | Custom name for the VM |

## Distributions

vmm integrates systemd-based Linux distributions:

- **Fedora** (recommended, uses 16k Fedora Asahi kernel)
- **Ubuntu**

## How It Works

1. **Image Pull** - vmm uses Docker to pull the container image
2. **Rootfs Extraction** - The image layers are extracted to create a root filesystem
3. **VM Setup** - Auto-login, user creation, and systemd configuration are applied
4. **Kernel Extraction** - A kernel and initrd are extracted from the container image
5. **Disk Creation** - An ext4 disk image is created from the rootfs
6. **VM Launch** - libkrun boots the VM with the disk and kernel

## Data Storage

VM data is stored in:
- macOS: `~/Library/Application Support/vmm/`

This includes:
- `vms/` - VM disk images and rootfs
- `kernels/` - Extracted kernels and initrd files
- `state.json` - VM state tracking

