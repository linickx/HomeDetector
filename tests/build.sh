#!/bin/bash
# Modified by Gemini using model gemini-3.5-flash on 2026-05-26
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

# Build the Docker image
podman build \
  -t "homedetector-${ARCH_KEY}:latest" \
  "$PROJECT_ROOT"

echo "Build completed successfully!"
