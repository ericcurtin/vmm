#!/bin/bash
# Build script for vmm that builds libkrun-efi from source and handles code signing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBKRUN_DIR="$SCRIPT_DIR/vendor/libkrun"
LIBKRUN_OUT="$SCRIPT_DIR/target/libkrun"

# Check if libkrun submodule is initialized
if [ ! -f "$LIBKRUN_DIR/Cargo.toml" ]; then
    echo "Initializing libkrun submodule..."
    git submodule update --init --recursive
fi

# Determine if we're building release or debug
if [[ "$*" == *"--release"* ]]; then
    PROFILE="release"
    CARGO_PROFILE_FLAG="--release"
else
    PROFILE="debug"
    CARGO_PROFILE_FLAG=""
fi

# Build libkrun with efi feature
echo "Building libkrun-efi from source..."
mkdir -p "$LIBKRUN_OUT"

pushd "$LIBKRUN_DIR" > /dev/null

# Create a dummy init binary for EFI builds
# The init binary is included in virtio-fs passthrough code but not used for EFI boots
# which use the guest's own init system from the disk image
if [ ! -f "init/init" ]; then
    echo "Creating placeholder init binary for EFI build..."
    echo -n "PLACEHOLDER" > init/init
fi

# Build libkrun with cargo - build the whole workspace with efi feature
# This ensures all dependent crates get the feature flags
# Note: krun_input and krun_display require libclang (install via: brew install llvm)
cargo build $CARGO_PROFILE_FLAG --features efi

# Copy the built library to our target directory
if [[ "$(uname)" == "Darwin" ]]; then
    LIBKRUN_SRC="$LIBKRUN_DIR/target/$PROFILE/libkrun.dylib"
    LIBKRUN_DST="$LIBKRUN_OUT/libkrun-efi.dylib"

    if [ -f "$LIBKRUN_SRC" ]; then
        cp "$LIBKRUN_SRC" "$LIBKRUN_DST"

        # Update the install name to use @rpath so it can be found at runtime
        install_name_tool -id "@rpath/libkrun-efi.dylib" "$LIBKRUN_DST"

        echo "Copied and configured libkrun at $LIBKRUN_DST"
    else
        echo "Error: libkrun library not found at $LIBKRUN_SRC"
        ls -la "$LIBKRUN_DIR/target/$PROFILE/" || true
        exit 1
    fi
else
    LIBKRUN_SRC="$LIBKRUN_DIR/target/$PROFILE/libkrun.so"
    LIBKRUN_DST="$LIBKRUN_OUT/libkrun-efi.so"

    if [ -f "$LIBKRUN_SRC" ]; then
        cp "$LIBKRUN_SRC" "$LIBKRUN_DST"
        echo "Copied libkrun to $LIBKRUN_DST"
    else
        echo "Error: libkrun library not found at $LIBKRUN_SRC"
        ls -la "$LIBKRUN_DIR/target/$PROFILE/" || true
        exit 1
    fi
fi

popd > /dev/null

# Build vmm
echo "Building vmm..."
cargo build "$@"

# Determine target binary
if [[ "$PROFILE" == "release" ]]; then
    TARGET="target/release/vmm"
else
    TARGET="target/debug/vmm"
fi

# On macOS, fix the library reference and sign the binary
if [[ "$(uname)" == "Darwin" ]]; then
    # Update the vmm binary to look for libkrun-efi.dylib instead of libkrun.1.dylib
    install_name_tool -change libkrun.1.dylib "@rpath/libkrun-efi.dylib" "$TARGET"

    echo "Signing $TARGET with hypervisor entitlement..."
    codesign --force --sign - --entitlements vmm.entitlements "$TARGET"
    echo "Done!"
else
    echo "Non-macOS platform, skipping code signing"
fi
