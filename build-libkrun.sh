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
make EFI=1

# The EFI build produces libkrun.dylib which needs to be renamed to libkrun-efi.dylib
DYLIB="$LIBKRUN_DIR/target/release/libkrun.dylib"

if [ -f "$DYLIB" ]; then
    echo "Successfully built: $DYLIB"

    # Create the target directory for linking
    mkdir -p "$SCRIPT_DIR/target/libkrun"

    # Copy and rename to libkrun-efi.dylib for linking
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
