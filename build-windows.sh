#!/bin/bash

# Build script for Windows AMD64
echo "Building AD-report for Windows AMD64..."

# Check if cross-compilation target is installed
if ! rustup target list --installed | grep -q "x86_64-pc-windows-gnu"; then
    echo "Installing Windows AMD64 target..."
    rustup target add x86_64-pc-windows-gnu
fi

# Build for Windows
echo "Building release binary for Windows..."
cargo build --release --target x86_64-pc-windows-gnu

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Windows executable: target/x86_64-pc-windows-gnu/release/ad-report.exe"
    ls -la target/x86_64-pc-windows-gnu/release/ad-report.exe 2>/dev/null || echo "Binary not found"
else
    echo "Build failed!"
fi