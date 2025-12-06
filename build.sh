#!/bin/bash
# Build script for vmm that handles code signing for macOS Hypervisor.framework access

set -e

# Build the project
echo "Building vmm..."
cargo build "$@"

# Determine target directory
if [[ "$*" == *"--release"* ]]; then
    TARGET="target/release/vmm"
else
    TARGET="target/debug/vmm"
fi

# Sign with hypervisor entitlements on macOS
if [[ "$(uname)" == "Darwin" ]]; then
    echo "Signing $TARGET with hypervisor entitlement..."
    codesign --force --sign - --entitlements vmm.entitlements "$TARGET"
    echo "Done!"
else
    echo "Non-macOS platform, skipping code signing"
fi
