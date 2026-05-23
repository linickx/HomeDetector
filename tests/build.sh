#!/bin/bash
# Build script for HomeDetector using podman
# Created by GitHub Copilot CLI on 2026-02-06

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Detect architecture
ARCH="${1:-$(uname -m)}"
case "$ARCH" in
  x86_64)
    ARCH_KEY="amd64"
    ;;
  aarch64|arm64)
    ARCH_KEY="aarch64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

echo "Building for architecture: $ARCH_KEY"

# Extract BUILD_FROM from build.yaml
BUILD_FROM=$(grep -A 2 "^build_from:" "$PROJECT_ROOT/build.yaml" | grep "$ARCH_KEY:" | awk '{print $2}' | tr -d '"')

if [ -z "$BUILD_FROM" ]; then
  echo "Error: Could not find base image for architecture $ARCH_KEY in build.yaml"
  exit 1
fi

echo "Using base image: $BUILD_FROM"

# Build the Docker image
podman build \
  --build-arg BUILD_FROM="$BUILD_FROM" \
  -t homedetector-$ARCH_KEY:latest \
  "$PROJECT_ROOT"

echo "Build completed successfully!"
