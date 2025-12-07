#!/bin/bash
# Build libkrun-efi from the vendor submodule
# This script builds the EFI variant of libkrun for macOS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBKRUN_DIR="$SCRIPT_DIR/vendor/libkrun"

echo "Building libkrun-efi..."

cd "$LIBKRUN_DIR"

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust/cargo not found. Please install Rust first."
    exit 1
fi

# Set LIBCLANG_PATH for bindgen
# Try Xcode CLT first, then Xcode.app
if [ -f "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib" ]; then
    export LIBCLANG_PATH="/Library/Developer/CommandLineTools/usr/lib"
elif [ -f "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib" ]; then
    export LIBCLANG_PATH="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib"
elif [ -f "/opt/homebrew/opt/llvm/lib/libclang.dylib" ]; then
    export LIBCLANG_PATH="/opt/homebrew/opt/llvm/lib"
else
    echo "Warning: libclang not found. bindgen may fail."
fi

echo "Using LIBCLANG_PATH: $LIBCLANG_PATH"

# Also set DYLD_LIBRARY_PATH for runtime loading of libclang
export DYLD_LIBRARY_PATH="$LIBCLANG_PATH:$DYLD_LIBRARY_PATH"

# Build the EFI variant
make clean 2>/dev/null || true

# Build the init binary for aarch64 Linux using Docker
# This is required even for EFI builds because the code includes it via include_bytes!
echo "Building init binary for aarch64 Linux..."
if command -v docker &> /dev/null; then
    docker run --rm -v "$LIBKRUN_DIR/init:/init" -w /init fedora:latest \
        bash -c "dnf install -y gcc glibc-static >/dev/null 2>&1 && gcc -O2 -static -Wall -o init init.c"
    if [ -f "$LIBKRUN_DIR/init/init" ]; then
        echo "Init binary built successfully"
    else
        echo "Error: Failed to build init binary"
        exit 1
    fi
else
    echo "Error: Docker is required to build the init binary for aarch64 Linux"
    exit 1
fi

make EFI=1

# The EFI build produces libkrun-efi.dylib (renamed by the Makefile)
DYLIB="$LIBKRUN_DIR/target/release/libkrun-efi.dylib"

if [ -f "$DYLIB" ]; then
    echo "Successfully built: $DYLIB"

    # Create the target directory for linking
    mkdir -p "$SCRIPT_DIR/target/libkrun"

    # Copy to target directory
    cp "$DYLIB" "$SCRIPT_DIR/target/libkrun/libkrun-efi.dylib"

    # Update the install name so dyld can find it at runtime
    install_name_tool -id "@rpath/libkrun-efi.dylib" "$SCRIPT_DIR/target/libkrun/libkrun-efi.dylib"

    # Also copy the header file
    mkdir -p "$SCRIPT_DIR/target/libkrun/include"
    cp "$LIBKRUN_DIR/include/libkrun.h" "$SCRIPT_DIR/target/libkrun/include/"

    echo "Library ready at: $SCRIPT_DIR/target/libkrun/libkrun-efi.dylib"
else
    echo "Error: Library not found at expected location: $DYLIB"
    exit 1
fi
