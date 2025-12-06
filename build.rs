fn main() {
    // Add library search paths for libkrun-efi
    #[cfg(target_os = "macos")]
    {
        // Homebrew paths for ARM64 and x86_64
        println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-search=native=/usr/lib64");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }
}
