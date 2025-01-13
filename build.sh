#!/bin/bash

# Read version from Cargo.toml
VERSION=$(grep '^version = ' Cargo.toml | cut -d '"' -f 2)
PROJECT_NAME=$(grep '^name = ' Cargo.toml | cut -d '"' -f 2)

echo "Building $PROJECT_NAME version $VERSION"

# Create dist directory
mkdir -p dist

# Build for Windows
echo "Building for Windows..."
cross build --target x86_64-pc-windows-gnu --release
cp "target/x86_64-pc-windows-gnu/release/${PROJECT_NAME}.exe" "dist/${PROJECT_NAME}-${VERSION}-windows.exe"

# Build for Linux
echo "Building for Linux..."
cross build --target x86_64-unknown-linux-gnu --release
cp "target/x86_64-unknown-linux-gnu/release/${PROJECT_NAME}" "dist/${PROJECT_NAME}-${VERSION}-linux"

# Build for macOS
echo "Building for macOS..."
cross build --target x86_64-apple-darwin --release
cp "target/x86_64-apple-darwin/release/${PROJECT_NAME}" "dist/${PROJECT_NAME}-${VERSION}-macos"

# Make Linux and macOS binaries executable
chmod +x "dist/${PROJECT_NAME}-${VERSION}-linux"
chmod +x "dist/${PROJECT_NAME}-${VERSION}-macos"

# Create archives
cd dist
zip "${PROJECT_NAME}-${VERSION}-windows.zip" "${PROJECT_NAME}-${VERSION}-windows.exe"
tar czf "${PROJECT_NAME}-${VERSION}-linux.tar.gz" "${PROJECT_NAME}-${VERSION}-linux"
tar czf "${PROJECT_NAME}-${VERSION}-macos.tar.gz" "${PROJECT_NAME}-${VERSION}-macos"

echo "Build complete! Executables are in the dist directory:"
ls -l
cd ..
