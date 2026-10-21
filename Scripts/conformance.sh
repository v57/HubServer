#!/bin/sh
# Core/hub-server's raw-protocol conformance harness (protocol.md) against hub-server-swift.
# Needs ../hub-server with its node_modules (bun install there).
set -e
cd "$(dirname "$0")/.."
swift build --product hub-server-swift
HUB_SERVER_CMD="$PWD/.build/debug/hub-server-swift" exec bun ../hub-server/test/conformance/e2e-hub.ts
