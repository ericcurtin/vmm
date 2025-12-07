//! VM setup and rootfs preparation
//!
//! This module handles converting a container image's filesystem into a
//! bootable VM rootfs with auto-login configured.

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::{debug, info};

/// Information about the host user to create in the VM
#[derive(Debug, Clone)]
pub struct HostUserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: String,
    pub shell: String,
}

impl HostUserInfo {
    /// Get the current user's information
    pub fn current() -> Result<Self> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Get username from environment or passwd entry
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| format!("user{}", uid));

        // Get home directory
        let home_dir = std::env::var("HOME")
            .unwrap_or_else(|_| format!("/home/{}", username));

        // Default shell
        let shell = std::env::var("SHELL")
            .unwrap_or_else(|_| "/bin/bash".to_string());

        Ok(Self {
            username,
            uid,
            gid,
            home_dir,
            shell,
        })
    }
}

/// Detect the distribution type from the rootfs
///
/// Only systemd-based distros are supported (Ubuntu, Fedora, Debian, etc.)
pub fn detect_distro(rootfs: &Path) -> Result<String> {
    // Check /etc/os-release
    let os_release = rootfs.join("etc/os-release");
    if os_release.exists() {
        let content = std::fs::read_to_string(&os_release)?;

        if content.contains("Ubuntu") || content.contains("ubuntu") {
            return Ok("ubuntu".to_string());
        }
        if content.contains("Fedora") || content.contains("fedora") {
            return Ok("fedora".to_string());
        }
        if content.contains("Debian") || content.contains("debian") {
            return Ok("ubuntu".to_string()); // Debian-like, uses same setup
        }
    }

    // Check for package managers (systemd distros only)
    if rootfs.join("usr/bin/apt").exists() || rootfs.join("usr/bin/apt-get").exists() {
        return Ok("ubuntu".to_string());
    }
    if rootfs.join("usr/bin/dnf").exists() || rootfs.join("usr/bin/yum").exists() {
        return Ok("fedora".to_string());
    }

    // Default to generic (will require systemd)
    Ok("generic".to_string())
}

/// Prepare the VM rootfs with auto-login and necessary configurations
pub async fn prepare_vm_rootfs(rootfs: &Path, distro: &str, command: &[String]) -> Result<()> {
    // Get host user info for creating matching user in VM
    let host_user = HostUserInfo::current()?;
    prepare_vm_rootfs_with_user(rootfs, distro, command, &host_user).await
}

/// Prepare the VM rootfs with a specific user configuration
pub async fn prepare_vm_rootfs_with_user(
    rootfs: &Path,
    distro: &str,
    command: &[String],
    host_user: &HostUserInfo,
) -> Result<()> {
    info!("Preparing VM rootfs for {} at {:?}", distro, rootfs);

    // Create essential directories if missing
    create_essential_dirs(rootfs)?;

    // Create the host user in the VM
    setup_host_user(rootfs, host_user)?;

    // Set up auto-login for the host user (not root)
    setup_auto_login_user(rootfs, distro, host_user)?;

    // Create init system configuration
    setup_init_with_user(rootfs, distro, host_user)?;

    // Set up networking
    setup_networking(rootfs, distro)?;

    // Set up console for the host user
    setup_console_user(rootfs, distro, command, host_user)?;

    // Set proper permissions
    fix_permissions(rootfs)?;

    info!("VM rootfs preparation complete");
    Ok(())
}

fn create_essential_dirs(rootfs: &Path) -> Result<()> {
    let dirs = [
        "proc", "sys", "dev", "dev/pts", "run", "tmp", "var/log",
        "etc/init.d", "etc/rc.d", "root", "home",
    ];

    for dir in dirs {
        let path = rootfs.join(dir);
        // Skip if path exists (including as a symlink)
        if path.exists() || path.is_symlink() {
            continue;
        }
        std::fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create {}", dir))?;
    }

    // Handle var/run specially - it's often a symlink to /run
    let var_run = rootfs.join("var/run");
    if !var_run.exists() && !var_run.is_symlink() {
        // Try to create it, but don't fail if it already exists
        let _ = std::fs::create_dir_all(&var_run);
    }

    // Set tmp permissions
    let tmp = rootfs.join("tmp");
    if tmp.exists() && !tmp.is_symlink() {
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o1777));
    }

    Ok(())
}

/// Create the host user in the VM with matching UID/GID
fn setup_host_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    debug!("Creating user {} with UID {} GID {}", user.username, user.uid, user.gid);

    // Create user's home directory (will be mount point for virtiofs)
    let user_home = rootfs.join(user.home_dir.trim_start_matches('/'));
    std::fs::create_dir_all(&user_home)?;

    // Add user's group to /etc/group
    let group_path = rootfs.join("etc/group");
    let mut group_content = if group_path.exists() {
        std::fs::read_to_string(&group_path).unwrap_or_default()
    } else {
        String::new()
    };

    // Ensure root group exists
    if !group_content.contains("root:") {
        group_content = format!("root:x:0:\n{}", group_content);
    }

    // Add user's group if not exists
    let user_group_entry = format!("{}:x:{}:", user.username, user.gid);
    if !group_content.contains(&format!("{}:", user.username)) && !group_content.contains(&format!(":{}:", user.gid)) {
        group_content.push_str(&format!("{}\n", user_group_entry));
    }

    std::fs::write(&group_path, group_content)?;

    // Add user to /etc/passwd
    let passwd_path = rootfs.join("etc/passwd");
    let mut passwd_content = if passwd_path.exists() {
        std::fs::read_to_string(&passwd_path).unwrap_or_default()
    } else {
        String::new()
    };

    // Ensure root user exists
    if !passwd_content.contains("root:") {
        passwd_content = format!("root:x:0:0:root:/root:/bin/bash\n{}", passwd_content);
    }

    // Add user if not exists
    // Use /bin/bash as shell since that's what we set up in the VM
    let user_passwd_entry = format!(
        "{}:x:{}:{}:{}:{}:/bin/bash",
        user.username,
        user.uid,
        user.gid,
        user.username,
        user.home_dir
    );
    if !passwd_content.contains(&format!("{}:", user.username)) {
        passwd_content.push_str(&format!("{}\n", user_passwd_entry));
    }

    std::fs::write(&passwd_path, passwd_content)?;

    // Add user to /etc/shadow with empty password
    let shadow_path = rootfs.join("etc/shadow");
    let _ = std::fs::set_permissions(&shadow_path, std::fs::Permissions::from_mode(0o640));

    let mut shadow_content = if shadow_path.exists() {
        std::fs::read_to_string(&shadow_path).unwrap_or_default()
    } else {
        String::new()
    };

    // Ensure root shadow entry
    if !shadow_content.contains("root:") {
        shadow_content = format!("root::19000:0:99999:7:::\n{}", shadow_content);
    }

    // Add user shadow entry if not exists
    let user_shadow_entry = format!("{}::19000:0:99999:7:::", user.username);
    if !shadow_content.contains(&format!("{}:", user.username)) {
        shadow_content.push_str(&format!("{}\n", user_shadow_entry));
    }

    std::fs::write(&shadow_path, shadow_content)?;

    // Set ownership of home directory
    // Note: This won't actually change ownership since we're running as a user,
    // but it sets up the structure. The virtiofs mount will handle actual ownership.
    let _ = std::fs::set_permissions(&user_home, std::fs::Permissions::from_mode(0o755));

    // Set up passwordless sudo for the user
    setup_passwordless_sudo(rootfs, user)?;

    Ok(())
}

/// Configure passwordless sudo for the user
fn setup_passwordless_sudo(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // Ensure sudoers.d directory exists
    let sudoers_d = rootfs.join("etc/sudoers.d");
    std::fs::create_dir_all(&sudoers_d)?;

    // Create a sudoers file for the user with NOPASSWD
    let sudoers_file = sudoers_d.join(&user.username);
    let sudoers_content = format!("{} ALL=(ALL) NOPASSWD: ALL\n", user.username);
    std::fs::write(&sudoers_file, &sudoers_content)?;

    // Set correct permissions (sudoers files must be 0440)
    std::fs::set_permissions(&sudoers_file, std::fs::Permissions::from_mode(0o440))?;

    // Also add user to wheel/sudo group in /etc/group
    let group_path = rootfs.join("etc/group");
    if group_path.exists() {
        let mut content = std::fs::read_to_string(&group_path)?;

        // Add user to wheel group if it exists
        if content.contains("wheel:") {
            content = content.replace(
                "wheel:x:10:",
                &format!("wheel:x:10:{}", user.username)
            );
        }

        // Add user to sudo group if it exists (Debian/Ubuntu)
        if content.contains("sudo:") && !content.contains(&format!("sudo:x:27:{}", user.username)) {
            content = content.replace(
                "sudo:x:27:",
                &format!("sudo:x:27:{}", user.username)
            );
        }

        std::fs::write(&group_path, content)?;
    }

    debug!("Configured passwordless sudo for user {}", user.username);
    Ok(())
}

/// Set up auto-login for the host user
fn setup_auto_login_user(rootfs: &Path, distro: &str, user: &HostUserInfo) -> Result<()> {
    debug!("Setting up auto-login for user {}", user.username);

    // Also ensure root can login (needed for some operations)
    let shadow_path = rootfs.join("etc/shadow");
    if shadow_path.exists() {
        let _ = std::fs::set_permissions(&shadow_path, std::fs::Permissions::from_mode(0o640));
    }

    // Set up systemd getty auto-login (all supported distros use systemd)
    setup_systemd_autologin_user(rootfs, user)?;

    Ok(())
}

fn setup_systemd_autologin_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // Create override for serial-getty on hvc0
    let getty_dir = rootfs.join("etc/systemd/system/serial-getty@hvc0.service.d");
    std::fs::create_dir_all(&getty_dir)?;

    let override_content = format!(r#"[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin {} --noclear %I $TERM
"#, user.username);

    std::fs::write(getty_dir.join("autologin.conf"), &override_content)?;

    // Also set up for ttyS0 as fallback
    let getty_dir_serial = rootfs.join("etc/systemd/system/serial-getty@ttyS0.service.d");
    std::fs::create_dir_all(&getty_dir_serial)?;
    std::fs::write(getty_dir_serial.join("autologin.conf"), &override_content)?;

    // Create symlink to enable the service
    let wants_dir = rootfs.join("etc/systemd/system/multi-user.target.wants");
    std::fs::create_dir_all(&wants_dir)?;

    let service_link = wants_dir.join("serial-getty@hvc0.service");
    if !service_link.exists() {
        let _ = std::os::unix::fs::symlink(
            "/lib/systemd/system/serial-getty@.service",
            &service_link,
        );
    }

    Ok(())
}

fn setup_alpine_autologin_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // For Alpine, modify inittab
    let inittab = rootfs.join("etc/inittab");
    let content = format!(r#"::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
ttyS0::respawn:/sbin/getty -n -l /bin/su - {} 115200 ttyS0
hvc0::respawn:/sbin/getty -n -l /bin/su - {} 115200 hvc0
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
"#, user.username, user.username);
    std::fs::write(&inittab, content)?;

    Ok(())
}

/// Set up init to run as the host user and mount home directory
fn setup_init_with_user(rootfs: &Path, distro: &str, user: &HostUserInfo) -> Result<()> {
    debug!("Setting up systemd for {} with user {}", distro, user.username);

    // Check if systemd exists
    let has_systemd = rootfs.join("lib/systemd/systemd").exists()
        || rootfs.join("usr/lib/systemd/systemd").exists();

    if !has_systemd {
        debug!("Systemd not found, it will be installed during kernel extraction");
        // Systemd will be installed when the kernel is extracted
        // Just set up the configuration directories
    }

    // For systemd, create a mount unit for the home directory
    setup_systemd_home_mount(rootfs, user)?;

    // Ensure systemd is the init - create symlink only if missing
    let init_link = rootfs.join("sbin/init");
    if !init_link.exists() {
        std::fs::create_dir_all(rootfs.join("sbin"))?;
        // Try both common paths for systemd
        if rootfs.join("lib/systemd/systemd").exists() {
            let _ = std::os::unix::fs::symlink("/lib/systemd/systemd", &init_link);
        } else {
            let _ = std::os::unix::fs::symlink("/usr/lib/systemd/systemd", &init_link);
        }
    }

    // Disable unnecessary services for faster boot
    let mask_services = [
        "systemd-networkd-wait-online.service",
        "NetworkManager-wait-online.service",
        "apt-daily.service",
        "apt-daily-upgrade.service",
        "unattended-upgrades.service",
    ];

    let mask_dir = rootfs.join("etc/systemd/system");
    std::fs::create_dir_all(&mask_dir)?;

    for service in mask_services {
        let link = mask_dir.join(service);
        if !link.exists() {
            let _ = std::os::unix::fs::symlink("/dev/null", &link);
        }
    }

    // Set default target to multi-user (console)
    let default_target = mask_dir.join("default.target");
    if !default_target.exists() {
        let _ = std::os::unix::fs::symlink(
            "/lib/systemd/system/multi-user.target",
            &default_target,
        );
    }

    Ok(())
}

fn setup_systemd_home_mount(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    // Create a systemd mount unit for the home directory
    let mount_dir = rootfs.join("etc/systemd/system");
    std::fs::create_dir_all(&mount_dir)?;

    // Convert home path to mount unit name (e.g., /home/user -> home-user.mount)
    let mount_unit_name = user.home_dir
        .trim_start_matches('/')
        .replace('/', "-");
    let mount_unit_file = mount_dir.join(format!("{}.mount", mount_unit_name));

    let mount_content = format!(r#"[Unit]
Description=Mount host home directory
Before=local-fs.target

[Mount]
What=home
Where={}
Type=virtiofs
Options=rw

[Install]
WantedBy=local-fs.target
"#, user.home_dir);

    std::fs::write(&mount_unit_file, mount_content)?;

    // Enable the mount unit
    let wants_dir = rootfs.join("etc/systemd/system/local-fs.target.wants");
    std::fs::create_dir_all(&wants_dir)?;
    let link = wants_dir.join(format!("{}.mount", mount_unit_name));
    if !link.exists() {
        let _ = std::os::unix::fs::symlink(
            format!("/etc/systemd/system/{}.mount", mount_unit_name),
            &link,
        );
    }

    Ok(())
}

fn setup_minimal_init_user(rootfs: &Path, user: &HostUserInfo) -> Result<()> {
    debug!("Setting up minimal init for user {}", user.username);

    // Create /sbin if it doesn't exist
    let sbin = rootfs.join("sbin");
    if !sbin.exists() {
        std::fs::create_dir_all(&sbin)?;
    }
    // Ensure /sbin is writable (some container images have it read-only)
    let _ = std::fs::set_permissions(&sbin, std::fs::Permissions::from_mode(0o755));

    // Create a minimal init script that mounts home and runs as user
    let init_script = rootfs.join("sbin/init");
    let content = format!(r#"#!/bin/sh
# Minimal init for vmm

# Mount essential filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null || true

# Mount the shared home directory via virtiofs
mkdir -p {home_dir}
mount -t virtiofs home {home_dir} 2>/dev/null || true

# Fix ownership of home directory
chown {uid}:{gid} {home_dir} 2>/dev/null || true

# Set up environment
export HOME={home_dir}
export TERM=linux
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export USER={username}

# Switch to user's home directory
cd {home_dir}

# Create a new session and run bash as the user with a controlling terminal
if command -v setsid >/dev/null 2>&1; then
    exec setsid -c su - {username} 2>/dev/null || exec su - {username}
else
    exec su - {username} 2>/dev/null || exec /bin/sh
fi
"#,
        home_dir = user.home_dir,
        uid = user.uid,
        gid = user.gid,
        username = user.username,
    );

    std::fs::write(&init_script, content)?;
    std::fs::set_permissions(&init_script, std::fs::Permissions::from_mode(0o755))?;

    Ok(())
}

/// Set up console/shell environment for the host user
fn setup_console_user(rootfs: &Path, distro: &str, command: &[String], user: &HostUserInfo) -> Result<()> {
    debug!("Setting up console for user {}", user.username);

    // Create /etc/securetty if it doesn't exist (allow user login on console)
    let securetty = rootfs.join("etc/securetty");
    if !securetty.exists() {
        let content = "console\ntty1\nttyS0\nhvc0\n";
        std::fs::write(&securetty, content)?;
    } else {
        let _ = std::fs::set_permissions(&securetty, std::fs::Permissions::from_mode(0o644));
        if let Ok(content) = std::fs::read_to_string(&securetty) {
            if !content.contains("hvc0") {
                let _ = std::fs::write(&securetty, format!("{}\nhvc0\n", content));
            }
        }
    }

    // Ensure user home directory exists and is writable
    let user_home = rootfs.join(user.home_dir.trim_start_matches('/'));
    if user_home.exists() {
        let _ = std::fs::set_permissions(&user_home, std::fs::Permissions::from_mode(0o755));
    } else {
        std::fs::create_dir_all(&user_home)?;
    }

    // Set up user's bash profile for interactive mode
    let bashrc = user_home.join(".bashrc");
    if bashrc.exists() {
        let _ = std::fs::set_permissions(&bashrc, std::fs::Permissions::from_mode(0o644));
    }

    // Interactive mode - write normal bashrc
    let bashrc_content = format!(r#"# ~/.bashrc
export PS1='\[\033[01;32m\]\u@vmm\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
export TERM=xterm-256color
export HOME={home_dir}
alias ls='ls --color=auto'
alias ll='ls -la'
alias grep='grep --color=auto'
cd {home_dir}
"#, home_dir = user.home_dir);
    let _ = std::fs::write(&bashrc, bashrc_content);

    // If a command is specified, create a systemd service to run it
    if !command.is_empty() {
        setup_systemd_command_service(rootfs, command, user)?;
    }

    // Create .profile
    let profile = user_home.join(".profile");
    if profile.exists() {
        let _ = std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o644));
    }
    let _ = std::fs::write(&profile, "# .profile\n");

    Ok(())
}

/// Create a systemd service to run a command and power off
fn setup_systemd_command_service(rootfs: &Path, command: &[String], user: &HostUserInfo) -> Result<()> {
    let system_dir = rootfs.join("etc/systemd/system");
    std::fs::create_dir_all(&system_dir)?;

    // Escape the command for shell
    let escaped_cmd: Vec<String> = command.iter()
        .map(|arg| shell_escape(arg))
        .collect();
    let cmd_str = escaped_cmd.join(" ");

    // Create the service unit
    let service_content = format!(r#"[Unit]
Description=VMM Command Execution
After=multi-user.target
Wants=multi-user.target

[Service]
Type=oneshot
User={username}
Group={username}
WorkingDirectory={home_dir}
Environment=HOME={home_dir}
Environment=TERM=xterm-256color
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/hvc0
TTYReset=yes
TTYVHangup=yes
ExecStart=/bin/bash -c '{cmd}'
ExecStopPost=/sbin/poweroff -f

[Install]
WantedBy=multi-user.target
"#,
        username = user.username,
        home_dir = user.home_dir,
        cmd = cmd_str.replace('\'', "'\\''"),
    );

    std::fs::write(system_dir.join("vmm-command.service"), service_content)?;

    // Enable the service
    let wants_dir = system_dir.join("multi-user.target.wants");
    std::fs::create_dir_all(&wants_dir)?;
    let link = wants_dir.join("vmm-command.service");
    if !link.exists() {
        let _ = std::os::unix::fs::symlink(
            "/etc/systemd/system/vmm-command.service",
            &link,
        );
    }

    // When running a command, disable the getty auto-login
    // so the command service takes the console
    let getty_link = wants_dir.join("serial-getty@hvc0.service");
    if getty_link.exists() || getty_link.is_symlink() {
        let _ = std::fs::remove_file(&getty_link);
    }

    Ok(())
}

fn setup_auto_login(rootfs: &Path, distro: &str) -> Result<()> {
    debug!("Setting up auto-login for {}", distro);

    // Create /etc/passwd entry for root if missing
    let passwd_path = rootfs.join("etc/passwd");
    if passwd_path.exists() {
        let content = std::fs::read_to_string(&passwd_path)?;
        if !content.contains("root:") {
            let new_content = format!("root:x:0:0:root:/root:/bin/bash\n{}", content);
            std::fs::write(&passwd_path, new_content)?;
        }
    } else {
        std::fs::write(&passwd_path, "root:x:0:0:root:/root:/bin/bash\n")?;
    }

    // Create /etc/shadow with empty password for root
    let shadow_path = rootfs.join("etc/shadow");
    if shadow_path.exists() {
        // Some container images have shadow with no read permissions - fix that first
        let _ = std::fs::set_permissions(&shadow_path, std::fs::Permissions::from_mode(0o640));

        // Try to read and modify, fallback to overwriting if read fails
        match std::fs::read_to_string(&shadow_path) {
            Ok(content) => {
                // Replace root's password hash with empty (allow passwordless login)
                let new_content = content
                    .lines()
                    .map(|line| {
                        if line.starts_with("root:") {
                            "root::19000:0:99999:7:::"
                        } else {
                            line
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                std::fs::write(&shadow_path, new_content + "\n")?;
            }
            Err(_) => {
                // If we still can't read, just overwrite with a basic shadow
                std::fs::write(&shadow_path, "root::19000:0:99999:7:::\n")?;
            }
        }
    } else {
        std::fs::write(&shadow_path, "root::19000:0:99999:7:::\n")?;
    }

    // Create /etc/group if missing
    let group_path = rootfs.join("etc/group");
    if !group_path.exists() {
        std::fs::write(&group_path, "root:x:0:\n")?;
    }

    // Set up getty auto-login based on distro
    match distro {
        "ubuntu" | "debian" => setup_systemd_autologin(rootfs)?,
        "fedora" => setup_systemd_autologin(rootfs)?,
        "alpine" => setup_alpine_autologin(rootfs)?,
        _ => setup_generic_autologin(rootfs)?,
    }

    Ok(())
}

fn setup_systemd_autologin(rootfs: &Path) -> Result<()> {
    // Create override for serial-getty on hvc0
    let getty_dir = rootfs.join("etc/systemd/system/serial-getty@hvc0.service.d");
    std::fs::create_dir_all(&getty_dir)?;

    let override_content = r#"[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
"#;

    std::fs::write(getty_dir.join("autologin.conf"), override_content)?;

    // Also set up for ttyS0 as fallback
    let getty_dir_serial = rootfs.join("etc/systemd/system/serial-getty@ttyS0.service.d");
    std::fs::create_dir_all(&getty_dir_serial)?;
    std::fs::write(getty_dir_serial.join("autologin.conf"), override_content)?;

    // Create symlink to enable the service
    let wants_dir = rootfs.join("etc/systemd/system/multi-user.target.wants");
    std::fs::create_dir_all(&wants_dir)?;

    let service_link = wants_dir.join("serial-getty@hvc0.service");
    if !service_link.exists() {
        let _ = std::os::unix::fs::symlink(
            "/lib/systemd/system/serial-getty@.service",
            &service_link,
        );
    }

    Ok(())
}

fn setup_alpine_autologin(rootfs: &Path) -> Result<()> {
    // For Alpine, modify inittab
    let inittab = rootfs.join("etc/inittab");
    if inittab.exists() {
        let content = std::fs::read_to_string(&inittab)?;
        let new_content = content.replace(
            "ttyS0::respawn:/sbin/getty",
            "ttyS0::respawn:/sbin/getty -n -l /bin/sh",
        );
        std::fs::write(&inittab, new_content)?;
    } else {
        let content = r#"::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
ttyS0::respawn:/sbin/getty -n -l /bin/sh 115200 ttyS0
hvc0::respawn:/sbin/getty -n -l /bin/sh 115200 hvc0
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
"#;
        std::fs::write(&inittab, content)?;
    }

    Ok(())
}

fn setup_generic_autologin(rootfs: &Path) -> Result<()> {
    // Create a simple init script that runs bash
    let init_script = rootfs.join("init");
    let content = r#"#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
export HOME=/root
export TERM=linux
cd /root
exec /bin/bash -l
"#;
    std::fs::write(&init_script, content)?;
    std::fs::set_permissions(&init_script, std::fs::Permissions::from_mode(0o755))?;

    Ok(())
}

fn setup_init(rootfs: &Path, distro: &str) -> Result<()> {
    debug!("Setting up init for {}", distro);

    // Check if systemd exists
    let has_systemd = rootfs.join("lib/systemd/systemd").exists()
        || rootfs.join("usr/lib/systemd/systemd").exists();

    // Check if any init exists
    let has_init = rootfs.join("sbin/init").exists()
        || rootfs.join("init").exists();

    if has_systemd {
        // Ensure systemd is the init
        let init_link = rootfs.join("sbin/init");
        if !init_link.exists() {
            std::fs::create_dir_all(rootfs.join("sbin"))?;
            let _ = std::os::unix::fs::symlink("/lib/systemd/systemd", &init_link);
        }

        // Disable unnecessary services for faster boot
        let mask_services = [
            "systemd-networkd-wait-online.service",
            "NetworkManager-wait-online.service",
            "apt-daily.service",
            "apt-daily-upgrade.service",
            "unattended-upgrades.service",
        ];

        let mask_dir = rootfs.join("etc/systemd/system");
        std::fs::create_dir_all(&mask_dir)?;

        for service in mask_services {
            let link = mask_dir.join(service);
            if !link.exists() {
                let _ = std::os::unix::fs::symlink("/dev/null", &link);
            }
        }

        // Set default target
        let default_target = mask_dir.join("default.target");
        if !default_target.exists() {
            let _ = std::os::unix::fs::symlink(
                "/lib/systemd/system/multi-user.target",
                &default_target,
            );
        }
    } else if !has_init {
        // No init at all - create a minimal one that runs bash
        // This is common for minimal container images
        setup_minimal_init(rootfs)?;
    }

    Ok(())
}

fn setup_minimal_init(rootfs: &Path) -> Result<()> {
    debug!("Setting up minimal init for container image");

    // Create /sbin if it doesn't exist
    let sbin = rootfs.join("sbin");
    if !sbin.exists() {
        std::fs::create_dir_all(&sbin)?;
    }
    // Ensure /sbin is writable (some container images have it read-only)
    let _ = std::fs::set_permissions(&sbin, std::fs::Permissions::from_mode(0o755));

    // Create a minimal init script
    let init_script = rootfs.join("sbin/init");
    let content = r#"#!/bin/sh
# Minimal init for vmm

# Mount essential filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null || true

# Set up environment
export HOME=/root
export TERM=linux
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Run shell from root's home
cd /root

# Create a new session and run bash with a controlling terminal
# Use setsid to create a new session, then exec bash
# The -c option of setsid creates a new controlling terminal
if command -v setsid >/dev/null 2>&1; then
    exec setsid -c /bin/bash --login 2>/dev/null || exec /bin/bash --login
else
    exec /bin/bash --login 2>/dev/null || exec /bin/sh
fi
"#;
    std::fs::write(&init_script, content)?;
    std::fs::set_permissions(&init_script, std::fs::Permissions::from_mode(0o755))?;

    Ok(())
}

fn setup_networking(rootfs: &Path, distro: &str) -> Result<()> {
    debug!("Setting up networking for {}", distro);

    // Create /etc/hosts
    let hosts = rootfs.join("etc/hosts");
    if !hosts.exists() {
        std::fs::write(
            &hosts,
            "127.0.0.1 localhost\n::1 localhost\n",
        )?;
    }

    // Create /etc/hostname
    let hostname = rootfs.join("etc/hostname");
    if !hostname.exists() {
        std::fs::write(&hostname, "vmm\n")?;
    }

    // Create /etc/resolv.conf
    let resolv = rootfs.join("etc/resolv.conf");
    if !resolv.exists() {
        std::fs::write(&resolv, "nameserver 8.8.8.8\nnameserver 8.8.4.4\n")?;
    }

    // For systemd-based systems, configure networkd
    if rootfs.join("lib/systemd/systemd").exists() {
        let network_dir = rootfs.join("etc/systemd/network");
        std::fs::create_dir_all(&network_dir)?;

        // DHCP configuration for all ethernet interfaces
        let network_conf = r#"[Match]
Name=e*

[Network]
DHCP=yes
"#;
        std::fs::write(network_dir.join("80-dhcp.network"), network_conf)?;
    }

    Ok(())
}

fn setup_console(rootfs: &Path, distro: &str, command: &[String]) -> Result<()> {
    debug!("Setting up console for {}", distro);

    // Create /etc/securetty if it doesn't exist (allow root login on console)
    let securetty = rootfs.join("etc/securetty");
    if !securetty.exists() {
        let content = "console\ntty1\nttyS0\nhvc0\n";
        std::fs::write(&securetty, content)?;
    } else {
        // Ensure we can read it
        let _ = std::fs::set_permissions(&securetty, std::fs::Permissions::from_mode(0o644));
        // Add hvc0 if not present
        if let Ok(content) = std::fs::read_to_string(&securetty) {
            if !content.contains("hvc0") {
                let _ = std::fs::write(&securetty, format!("{}\nhvc0\n", content));
            }
        }
    }

    // Ensure root home directory exists and is writable
    let root_home = rootfs.join("root");
    if root_home.exists() {
        let _ = std::fs::set_permissions(&root_home, std::fs::Permissions::from_mode(0o700));
    } else {
        std::fs::create_dir_all(&root_home)?;
    }

    // Set up root's bash profile for a nicer experience
    let bashrc = root_home.join(".bashrc");
    // Fix permissions if the file exists
    if bashrc.exists() {
        let _ = std::fs::set_permissions(&bashrc, std::fs::Permissions::from_mode(0o644));
    }

    // If a command is specified, create a profile that runs the command and exits
    if !command.is_empty() {
        // Escape the command for shell
        let escaped_cmd: Vec<String> = command.iter()
            .map(|arg| shell_escape(arg))
            .collect();
        let cmd_str = escaped_cmd.join(" ");

        // Create a profile that runs the command and poweroffs
        // Use multiple methods to try to shutdown since not all images have poweroff
        let content = format!(r#"# ~/.bashrc - auto-generated for command execution
export TERM=xterm-256color
export HOME=/root
cd /root

# Run the specified command
{}

# Power off after command completes using multiple fallback methods
# Method 1: poweroff command
if command -v poweroff >/dev/null 2>&1; then
    exec poweroff -f
fi
# Method 2: halt command
if command -v halt >/dev/null 2>&1; then
    exec halt -f -p
fi
# Method 3: SysRq trigger (works on any Linux kernel)
echo o > /proc/sysrq-trigger 2>/dev/null || true
# Method 4: reboot syscall via shell (last resort)
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo o > /proc/sysrq-trigger 2>/dev/null || true
# If all else fails, just exit
exit 0
"#, cmd_str);
        let _ = std::fs::write(&bashrc, content);
    } else {
        // Interactive mode - write normal bashrc
        let content = r#"# ~/.bashrc
export PS1='\[\033[01;32m\]\u@vmm\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
export TERM=xterm-256color
alias ls='ls --color=auto'
alias ll='ls -la'
alias grep='grep --color=auto'
"#;
        let _ = std::fs::write(&bashrc, content);
    }

    // Create .profile - don't source bashrc again since bash --login already does
    let profile = root_home.join(".profile");
    if profile.exists() {
        let _ = std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o644));
    }
    // bash --login sources .profile, which can source .bashrc
    // But bash also sources .bashrc when interactive, so avoid double-sourcing
    let _ = std::fs::write(&profile, "# .profile\n");

    Ok(())
}

/// Escape a string for use in a shell command
fn shell_escape(s: &str) -> String {
    // If the string contains only safe characters, return as-is
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/') {
        return s.to_string();
    }
    // Otherwise, wrap in single quotes and escape any single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn fix_permissions(rootfs: &Path) -> Result<()> {
    // Fix permissions on sensitive files - ignore errors since they may already have correct perms
    let shadow = rootfs.join("etc/shadow");
    if shadow.exists() {
        let _ = std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o640));
    }

    let passwd = rootfs.join("etc/passwd");
    if passwd.exists() {
        let _ = std::fs::set_permissions(&passwd, std::fs::Permissions::from_mode(0o644));
    }

    // Make sure /root is accessible
    let root_home = rootfs.join("root");
    if root_home.exists() {
        let _ = std::fs::set_permissions(&root_home, std::fs::Permissions::from_mode(0o700));
    }

    Ok(())
}
