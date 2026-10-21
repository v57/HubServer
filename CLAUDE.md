# HubServer (Swift Hub server)

Swift package implementing `../../Docs/Devices/protocol.md`, the same contract as the TypeScript `../hub-server`
(the reference: when they differ, protocol.md decides, then hub-server's behaviour). See `README.md` for products,
options and the embedding API.

## Layout

- `Sources/ChannelServer`: JSON (`JSON`, ordered `JSONObject`), `WebSocketServer` on a `ByteStreamListener`
  (`NetworkStreamListener` = Network.framework), `ChannelPeer` (one connection, both directions), `ChannelRouter`.
- `Sources/HubServer`: `HubServer` (public API) → `Hub` (connections, routing, built-in routes), `Security`
  (tokens, modes, grants, groups, members, hosting, whitelist, `hub.json`), `Devices` (certificates, `devices.json`),
  `Services` (providers, balancers, apps), `Pairing`, `Store` (atomic JSON stores), `Live` (streams of current
  values), `Crypto` (SPKI/PKCS#8 keys, device ids, scrypt).
- `Sources/hub-server-swift`: the command. `Sources/channel-fixture`: routes of `Channel/channel/tests/server.ts`.

## Rules

- Everything in `Hub` and `ChannelServer` runs on one serial queue; nothing blocks it (pairing checks sleep on the
  pairing queue, file writes go to the storage queue). New code keeps that confinement.
- Store files keep hub-server's names and formats, so a data directory works with either server.
- Hub errors stay plain strings (protocol.md section 11); add `code` only where channel itself has one.
- Language mode is Swift 5 for the targets; the public API is `Sendable`.

## Tests

`swift test`; `swift build --product channel-fixture && bun test Tests/interop`; `Scripts/conformance.sh` (needs
`../hub-server` with `bun install`); `Scripts/sdk-live.sh`. Build for devices with
`xcodebuild -scheme HubServer -destination 'generic/platform=iOS' build`. Pick test ports that are free: other
sessions run hubs on 1997, 2097, 2197, 2297.
