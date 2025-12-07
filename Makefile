.PHONY: build release debug sign clean install

# Default target
all: release

# Build and sign release binary
release:
	cargo build --release
	codesign --sign - --entitlements entitlements.plist --force ./target/release/vmm

# Build and sign debug binary
debug:
	cargo build
	codesign --sign - --entitlements entitlements.plist --force ./target/debug/vmm

# Just sign (useful after cargo build)
sign:
	@if [ -f ./target/release/vmm ]; then \
		codesign --sign - --entitlements entitlements.plist --force ./target/release/vmm; \
		echo "Signed release binary"; \
	fi
	@if [ -f ./target/debug/vmm ]; then \
		codesign --sign - --entitlements entitlements.plist --force ./target/debug/vmm; \
		echo "Signed debug binary"; \
	fi

# Install to /usr/local/bin
install: release
	cp ./target/release/vmm /usr/local/bin/vmm

# Clean build artifacts
clean:
	cargo clean
