#!/bin/sh
# The TS SDK (HubService/hub-service) and the Swift SDK's live suites (HubService/HubService) against
# hub-server-swift. The Swift SDK runs from a git archive in a temp directory, built against the local
# Channel/ChannelSwift, so the HubService checkout is left alone.
set -e
cd "$(dirname "$0")/.."
root="$PWD"
hub="$(cd ../.. && pwd)"
swift build --product hub-server-swift
binary="$root/.build/debug/hub-server-swift"
work="$(mktemp -d)"

echo "== TS SDK"
bun Tests/interop/sdk-ts.ts

echo "== Swift SDK"
port1=$((26000 + $$ % 1000)); port2=$((port1 + 1000))
trap 'pkill -f "hub-server-swift --port $port1"; pkill -f "hub-server-swift --port $port2"; rm -rf "$work"; true' EXIT
mkdir -p "$work/owned" "$work/pairing" "$work/HubService"
owner=$(cd "$work" && bun -e "const c=require('crypto');const k=c.generateKeyPairSync('ed25519',{privateKeyEncoding:{format:'der',type:'pkcs8'},publicKeyEncoding:{format:'der',type:'spki'}});require('fs').writeFileSync('owner.key',Buffer.concat([k.privateKey,k.publicKey]).toString('base64'));console.log(k.publicKey.toString('base64'))")
(cd "$work/owned" && HUB_DEVICE_KEY="$work/owned/device.key" "$binary" --port $port1 --owner "$owner" > hub.log 2>&1 &)
(cd "$work/pairing" && HUB_DEVICE_KEY="$work/pairing/device.key" "$binary" --port $port2 > hub.log 2>&1 &)
sleep 2
code=$(cat "$work/pairing/data/pairing-code")
git -C "$hub/HubService/HubService" archive HEAD | tar -x -C "$work/HubService"
sed -i '' "s|.package(url: \"https://github.com/v57/ChannelSwift.git\", branch: \"main\")|.package(path: \"$hub/Channel/ChannelSwift\")|g" "$work/HubService/Package.swift"
cd "$work/HubService"
HUB_LIVE_URL=ws://127.0.0.1:$port1 HUB_LIVE_OWNER_KEY="$work/owner.key" HUB_PAIR_URL=ws://127.0.0.1:$port2 HUB_PAIR_CODE="$code" \
  swift test --filter Live
