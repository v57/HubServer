# HubServer

## Purpose

`HubServer` is a Hub server in Swift. An app embeds it to become the hub its devices and services connect to (the Hub
app does this on iPhone, iPad and Mac), and `hub-server-swift` runs the same server from a terminal. It implements the
Hub protocol (`Docs/Devices/protocol.md` in the Hub workspace), the same contract as the TypeScript
[hub-server](https://github.com/v57/hub-server), keeps its data in hub-server's file formats, and passes
hub-server's conformance harness.

It is not a client: services and apps talk to a hub with the SDKs, [HubService](https://github.com/v57/HubService)
(Swift) and [hub-service](https://github.com/v57/hub-service) (TypeScript). The channel transport underneath is
[ChannelServer](ChannelServer.md), which `import HubServer` re-exports.

hub-server's developer pages describe the behaviour both servers share; this page links to them where they apply:
[security](https://github.com/v57/hub-server/blob/main/docs/security.md),
[APIs](https://github.com/v57/hub-server/blob/main/docs/api.md),
[data folder](https://github.com/v57/hub-server/blob/main/docs/data.md) and
[Hub Network](https://github.com/v57/hub-server/blob/main/docs/network.md).

## Getting started

```swift
// Package.swift
dependencies: [
  .package(url: "https://github.com/v57/HubServer.git", branch: "main"),
],
targets: [
  .target(name: "MyApp", dependencies: [.product(name: "HubServer", package: "HubServer")]),
]
```

Start a hub, show its pairing code, stop it:

```swift
import Foundation
import HubServer

let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
var configuration = HubServer.Configuration(dataDirectory: support.appendingPathComponent("Hub"))
configuration.listen = ListenAddress(port: 1997)
configuration.name = "Home"
let server = HubServer(configuration)

let port = try await server.start()        // loads the data directory, then listens
print("Hub \(server.status.hubKey ?? "") on port \(port)")
if let code = server.status.pairingCode {  // a hub without owners has one
  print("Pairing code \(code.code), valid until \(code.expires)")
  print(HubServer.pairingLink(address: "ws://my-mac.local:\(port)", code: code.code))
}

for await status in server.statusUpdates() {   // the current status, then every change
  print(status.state, status.connections, status.owners)
}

await server.stop()
```

## Main API

### `HubServer`

| | |
|---|---|
| `init(_ configuration: Configuration)` | Makes a server; nothing happens until `start()` |
| `start() async throws -> UInt16` | Loads the data directory and listens. Returns the port. Throws `HubServerError.alreadyRunning` or `.listen(_:)` |
| `stop() async` | Closes every connection, stops listening and writes pending changes |
| `status: Status` | A snapshot |
| `statusUpdates() -> AsyncStream<Status>` | The current status, then every change |
| `newPairingCode() async throws -> PairingCode` | A new code replacing the old one, as owners do with `hub/pair/new` |
| `addOwner(_ key: String) async throws` | Adds a service or device SPKI to the `owners` group |
| `static writePairingCode(dataDirectory:) throws -> PairingCode` | Writes a new code to a data directory, as `hub-server --pair` does; a hub running on it takes the code at once |
| `static pairingLink(address:code:) -> URL` | `hub://pair?a=<address>&c=<code>`, for a link or QR code the Hub app opens |

`HubServer` is thread-safe. The hub runs on its own serial queue, pairing checks on another; nothing runs on the main
actor.

### `HubServer.Configuration`

`Configuration(dataDirectory:)`, then set what you need:

| Property | Default | |
|---|---|---|
| `dataDirectory` | | Where the hub keeps its key (`auth`) and stores. Created (0700) if missing |
| `key` | `nil` | A `HubKeyPair` the app keeps itself, in place of the `auth` file |
| `listen` | `ListenAddress(port: 1997)` | Port and optional host; port 0 picks a free one |
| `local` | `false` | Local mode: 127.0.0.1 only, `default-allow`, not stored |
| `owners` | `[]` | Service or device SPKIs added to the `owners` group at start |
| `launcherKey` | `nil` | The launcher key: may host and call `launcher/*`, its device is approved at once. No owner |
| `devicePublicKey` | `nil` | This machine's device SPKI. The hub enrols it as its own approved device, with the hub key as its service. `nil`: the hub has no device |
| `deviceName` | the host name | The hub's device name |
| `platform` | from the OS | `macos`, `ios`, `visionos`, `tvos`, `linux`, ... (protocol section 3) |
| `instance` | `"hub-server"` | The hub's instance on its device |
| `host` | `nil` | What runs the hub, sent as `host` in `hub/info`. The Hub app sets `"app"` so its devices know the app is the hub's Hub Network agent |
| `name` | the host name | The hub's display name (`hub/header`) on a first start |
| `pairsAtStart` | `true` | Make a pairing code at start when the hub has no owners |
| `localAgentEndpoint` | `nil` | Where this machine's Hub Network agent proves itself: a Unix socket path, or `tcp://host:port`. `nil`: `/var/run/hub-net/agent.sock` on macOS, `/run/hub-net/agent.sock` on Linux |
| `log` | `print` | Where log lines go |

`Configuration.hostName` and `Configuration.hostPlatform` give the defaults.

### `Status`, `Peer`, `PairingCode`

- `Status`: `state` (`.stopped`, `.starting`, `.running`, `.failed(String)`), `port`, `hubKey` (the SPKI clients pin),
  `name`, `connections`, `peers`, `owners` (members of the owners group), `pairingCode`, `local`.
- `Peer`: one connection, oldest first: `id`, `name` (its profile's label), `device` (its device's name), `key`,
  `address`, `services` (paths it provides).
- `HubServer.PairingCode`: `code` (`K7Q-2MX`) and `expires`.

### Keys

`HubKeyPair` is an Ed25519 key in the Hub key file format (base64 of PKCS#8 then SPKI, protocol section 1):

| | |
|---|---|
| `init()`, `init(privateKey:)`, `init(fileText:) throws` | A new key, a CryptoKit key, or a key file's text |
| `publicKey: String`, `fileText: String` | The SPKI in base64, and the file text |
| `sign(_ message: String) -> String`, `sign(data:) -> String` | Base64 Ed25519 signatures |
| `static loadOrCreate(_ url: URL) throws -> HubKeyPair` | Reads a key file, or creates it (0600, atomically) |
| `static moved(from:load:save:) throws -> HubKeyPair` | The hub key from the app's own secure store, moving it there from the `auth` file once |

An app that keeps the hub key in its keychain passes it as `Configuration.key`. `moved` takes the store's raw 32-byte
private key through two closures you write, and removes the file only after the store gave the key back:

```swift
let directory = support.appendingPathComponent("Hub")
configuration.key = try HubKeyPair.moved(
  from: directory.appendingPathComponent("auth"),
  load: { try readHubKeyFromKeychain() },   // Data? : nil when the store has no key
  save: { try writeHubKeyToKeychain($0) }    // Data
)
```

A failing `load` stops there instead of making a new key, since a new key is a new hub for every device that pinned
the old one. To make the hub this machine's device, pass the device key's SPKI:

```swift
configuration.devicePublicKey = try HubKeyPair.loadOrCreate(deviceKeyURL).publicKey
```

Apple apps keep the device key in the keychain instead (protocol section 3, Device key location).

### Errors

`HubServerError`: `invalidKeyFile`, `keyNotStored` (the store didn't give the key back), `notRunning`,
`alreadyRunning`, `listen(String)`.

## Storage

The data directory holds `auth` (unless `Configuration.key` is set), the JSON stores and the pairing files, with
hub-server's names and formats: `hub.json`, `header.json`, `devices.json`, `grants.json`, `group-members.json`,
`groups.json`, `paths.json`, `services.json`, `whitelist.json`, `v1-keys.json`, `network.json`, `local-agent.json`,
`hub-net-node.json`, `pairing.json`, `pairing-code`. hub-server's
[data folder page](https://github.com/v57/hub-server/blob/main/docs/data.md) describes each. Writes go through a
temporary file and a rename, off the hub's queue.

- Keep the directory across launches: the hub key and the stores are the hub.
- A first start (no `auth` and no `hub.json`) is `default-deny`.
- A file that can't be parsed is moved aside (`<name>.corrupt-<time>`); a corrupt `hub.json`, `paths.json`,
  `whitelist.json`, `group-members.json`, `grants.json` or `devices.json` locks the hub down to owners until an owner
  sets the mode.
- A data directory works with either server. One from an old hub-pro with pre-grants stores (`clients.json`, path
  lists in `groups.json`, `group_users.json`) should be opened by hub-server once first: HubServer doesn't migrate
  them.

## The `hub-server-swift` command

```sh
swift run hub-server-swift --port 1997
```

| Option | |
|---|---|
| `-p`, `--port <port>` | A port, or `host:port` / `[::1]:port`. Default 1997, env `HUBLISTEN` |
| `--data <directory>` | The data directory. Default `./data`, like hub-server |
| `--owner <key>` | An owner SPKI, may be repeated. Env `HUBOWNER` (one key) |
| `--launcher <key>` | The launcher key. Env `HUBLAUNCHER` |
| `--local` | Local mode. Env `HUB_MODE=local` |
| `--net-agent <endpoint>` | The Hub Network agent's Unix socket, or `tcp://host:port` when the agent runs next to the hub in a container. Env `HUB_NET_AGENT_SOCKET` |
| `--pair` | Writes a new pairing code to the data directory, prints it and exits |
| `-h`, `--help` | Prints the options |

`--merge` and `--proxy` are read and ignored with a message; other unknown options print `Unknown option`. Empty
environment variables count as unset. The hub's device key is `HUB_DEVICE_KEY`, else `/var/lib/hub/device.key` for
root on Linux, else `~/.hub/device.key`, created if missing. SIGINT and SIGTERM stop the hub, writing pending changes,
and exit.

## What differs from hub-server

- **Not implemented:** merging and proxies (`hub/merge/add|remove`, `hub/proxy*`, `--merge`, `--proxy`;
  `hub/merge/status` streams `[]`), and migration of the pre-grants stores.
- **Embedding:** the data directory, the hub key and the device key come from the host (`Configuration`), and the
  host watches `Status` instead of reading stdout.
- **Options:** `--data` picks the data directory (hub-server always uses `./data`). `--net-agent` and
  `localAgentEndpoint` also take `tcp://host:port`; hub-server takes a socket path in `HUB_NET_AGENT_SOCKET` only.
- **`hub/info`** may carry `host` (`Configuration.host`).
- **Apple app agent:** the `hub/net/apple-agent/*` routes are always served; hub-server's
  `HUB_NET_APPLE_AGENT_ENABLED` and `HUB_NET_APPLE_AGENT_PROTOCOL_VERSION` aren't read.
- **Transport:** connections come through `ChannelServer`, one serial queue for the hub and all connections.

Everything else (tokens and the v0 transition, owners, grants, groups, hosting, the whitelist, devices and child
devices, pairing, local mode, routing and load balancers, draining, API descriptions, the Hub Network control plane)
follows hub-server, and the conformance harness checks it.

## Platform notes

| Platform | |
|---|---|
| macOS 13, Mac Catalyst 16 | Supported. Network.framework listener |
| iOS 16, iPadOS | Supported, embedded in the Hub app. Listening for other devices needs `NSLocalNetworkUsageDescription` (and `NSBonjourServices` if the app advertises the hub). iOS suspends the listener when the app goes to the background, so a phone or tablet is a hub only while the app runs or a background mode keeps it alive. There is no machine Hub Network agent on iOS: the app's packet tunnel binds as `apple-app` |
| tvOS 16, visionOS 1 | Builds with `xcodebuild`; not otherwise tested |
| Linux | Builds and serves: ChannelServer's POSIX socket listener and swift-crypto in place of CryptoKit |
| Windows | Not yet. The package pulls swift-crypto there, but ChannelServer has no listener for it, so `start()` ends in a fatal error |
| Android | Not yet |

The listener is plain WebSocket (`ws://`). ChannelServer can also serve QUIC on Apple platforms, but HubServer doesn't
listen on it yet.

## Testing

Commands from the package root:

```sh
swift test                      # JSON, WebSocket, peer, protocol vectors, security, pairing, an in-process hub, Hub Network
swift build --product channel-fixture && bun test Tests/interop   # the channel TS client against ChannelServer
Scripts/conformance.sh          # hub-server's conformance harness against hub-server-swift
Scripts/sdk-live.sh             # the TS SDK and the Swift SDK's live suites against hub-server-swift
xcodebuild -scheme HubServer -destination 'generic/platform=iOS' build
```

- `swift test` needs nothing else. `Tests/HubServerTests/Fixtures` holds the device vectors, a Go-signed join
  admission and the Hub Network signature vectors shared with hub-server.
- The interop tests and the scripts expect the Hub workspace layout: the channel TS client at
  `../../Channel/channel`, the SDKs under `../../HubService`, and hub-server at `../hub-server`.
- Tests and scripts pick their own ports; when other hubs run on the machine, keep away from the ports they use.

### The conformance harness

hub-server's `test/conformance/e2e-hub.ts` checks a server over the raw protocol: tokens, devices, caller identity,
default deny, grants, groups, pairing (including `--pair` next to a running server), local mode, API descriptions,
stores written by older versions, and more. `Scripts/conformance.sh` builds `hub-server-swift` and runs it:

```sh
(cd ../hub-server && bun install)
Scripts/conformance.sh
```

That is the same as:

```sh
swift build --product hub-server-swift
HUB_SERVER_CMD="$PWD/.build/debug/hub-server-swift" bun ../hub-server/test/conformance/e2e-hub.ts
```

It prints `PASS` or `FAIL` per check and exits non-zero when one fails. hub-server's
[testing page](https://github.com/v57/hub-server/blob/main/docs/testing.md#conformance-harness) describes how it runs
the server and its variables (`HUB_SERVER_CMD`, `HUB_SERVER_START_TIMEOUT`).
