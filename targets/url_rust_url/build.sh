#!/bin/bash
# Build Rust URL parser target
# Output: url_rust_url binary in target/release/
set -e
cd "$(dirname "$0")"
echo "Building Rust URL parser target..."
cargo build --release
echo "Done: target/release/url_rust_url.exe"
