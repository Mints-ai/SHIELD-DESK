#!/usr/bin/env bash
# Cross-platform compilation script for ShieldDesk Endpoint Agent
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../bin"
AGENT_DIR="${SCRIPT_DIR}/.."

mkdir -p "${OUTPUT_DIR}"
cd "${AGENT_DIR}"

echo "Building ShieldDesk Endpoint Agent for multiple platforms..."

# 1. Windows amd64
echo "--> Building windows/amd64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "${OUTPUT_DIR}/shielddesk-agent-windows-amd64.exe" ./cmd

# 2. Linux amd64
echo "--> Building linux/amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "${OUTPUT_DIR}/shielddesk-agent-linux-amd64" ./cmd

# 3. Linux arm64
echo "--> Building linux/arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "${OUTPUT_DIR}/shielddesk-agent-linux-arm64" ./cmd

# 4. Darwin arm64 (Apple Silicon)
echo "--> Building darwin/arm64..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "${OUTPUT_DIR}/shielddesk-agent-darwin-arm64" ./cmd

echo "[SUCCESS] All cross-platform binaries compiled to: ${OUTPUT_DIR}"
ls -lh "${OUTPUT_DIR}"
