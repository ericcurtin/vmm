fn main() {
    // Get the manifest directory (where Cargo.toml is)
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Add the local libkrun build directory first (highest priority)
    let local_libkrun = format!("{}/target/libkrun", manifest_dir);
    println!("cargo:rustc-link-search=native={}", local_libkrun);

    // Also set rpath so the library can be found at runtime
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", local_libkrun);
        // Fallback paths
        println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", local_libkrun);
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-search=native=/usr/lib64");
        println!("cargo:rustc-link-search=native=/usr/local/lib");
    }

    // Re-run build script if the library changes
    println!("cargo:rerun-if-changed={}/libkrun-efi.dylib", local_libkrun);
    println!("cargo:rerun-if-changed=build-libkrun.sh");
}
