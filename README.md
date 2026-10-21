# HubServer

A Hub server in Swift, so any device can be the hub: the Hub app on iPhone, iPad and Mac embeds it, and
`hub-server-swift` runs it from a terminal. It implements the device-layer protocol in
[`Docs/Devices/protocol.md`](../../Docs/Devices/protocol.md), the same contract as the TypeScript
[hub-server](../hub-server), and passes hub-server's raw-protocol conformance harness.

## Products

| Product | What |
|---|---|
| `HubServer` | the hub, with the embedding API below |
| `ChannelServer` | the server side of the [channel](../../Channel/channel) protocol: JSON, a WebSocket server on a byte-stream transport, the symmetric channel peer and a router |
| `hub-server-swift` | the hub as a command, with hub-server's options |

Apple platforms (macOS 13, iOS 16, tvOS 16, visionOS 1, Mac Catalyst 16). No dependencies.

## Run it

```sh
swift run hub-server-swift --port 1997
```

| Option | |
|---|---|
| `-p`, `--port <port>` | a port or `host:port` (default 1997, env `HUBLISTEN`) |
| `--data <directory>` | where the hub keeps its key and stores (default `./data`, like hub-server) |
| `--owner <key>` | trust this service or device SPKI as an owner (env `HUBOWNER`) |
| `--launcher <key>` | let this key host `launcher/*` and enrol its device at once (env `HUBLAUNCHER`) |
| `--local` | local mode: 127.0.0.1 only, `default-allow`, the launcher key is an owner, no pairing (env `HUB_MODE=local`) |
| `--pair` | write a new pairing code to the data directory, print it and exit; a hub running on it takes the code at once |

The hub's own device key is `HUB_DEVICE_KEY`, else `~/.hub/device.key` (created if missing). A hub without owners
prints `Pairing code: K7Q-2MX (valid until …)` at start and writes it to `data/pairing-code`.

## Embed it

```swift
import HubServer

var configuration = HubServer.Configuration(dataDirectory: appSupport.appendingPathComponent("Hub"))
configuration.listen = ListenAddress(port: 1997)          // ListenAddress(host: "127.0.0.1", port: 0) for a free local port
configuration.devicePublicKey = deviceKey.publicKey      // the app's device key (SPKI), so the hub is this device
configuration.deviceName = "iPad"
configuration.name = "Home"                              // hub/header name on a first start
let server = HubServer(configuration)

let port = try await server.start()                      // loads the data directory, then listens
for await status in server.statusUpdates() {             // current status first, then every change
  // status.state (.stopped/.starting/.running/.failed), status.port, status.hubKey, status.name,
  // status.connections, status.owners, status.pairingCode (code + expiry while the hub has one)
}
let code = try await server.newPairingCode()             // replaces the old one, like hub/pair/new
let link = HubServer.pairingLink(address: "ws://ipad.local:1997", code: code.code)   // hub://pair?a=…&c=…
try await server.addOwner(key)                           // a key or device SPKI
await server.stop()                                      // closes connections, writes pending changes
```

- **Data directory:** the host picks it. It holds `auth` (the hub key, 0600), the JSON stores and the pairing files,
  in hub-server's formats, written through a temp file and a rename. Keep it across launches: the hub key is what
  clients pin.
- **Owner pairing:** a hub without owners makes a code at start (`pairsAtStart`, on by default) and shows it in
  `status.pairingCode`. The first device that sends it with `hub/pair` becomes the owner (its key and its device),
  and the code is gone. The Hub app can also pair itself: connect to its own hub with its service key and device
  certificate and call `hub/pair`, or start the hub with `owners = [appServiceKey, appDevicePublicKey]`.
- **Local mode** (`local = true`): listens on 127.0.0.1 only, whatever `listen.host` says.
- **Threading:** `HubServer` is thread-safe; the hub runs on its own serial queue and pairing checks on another.
- **iOS:** listening for other devices needs `NSLocalNetworkUsageDescription` (and `NSBonjourServices` if the app
  advertises the hub); iOS suspends the listener when the app goes to the background, so a phone or tablet is a hub
  only while the app runs (or under a background mode that keeps it alive).
- **Other platforms:** the transport sits behind `ChannelTransport` (message connections) and `ByteStreamListener`
  (TCP). Apple platforms use Network.framework (`NetworkStreamListener`); Linux, Windows and Android ports
  (`~/Developer/v57/SwiftUI`) add a `ByteStreamListener` on sockets, or their own `ChannelTransport`, and swift-crypto
  in place of CryptoKit.

## What it implements

protocol.md sections 1–12:

- `hub/info`, v0 and v1 tokens (v1 bound to the hub key, 30 s skew, 300 s maximum lifetime), `requireV1`,
  the whitelist (lockdown mode)
- caller identity in `context.hub` of every forwarded request (client-supplied `hub` replaced)
- service registration (`hub/service/update` with `services`, `add/remove`, `apps`, `public`, `limit`,
  `permissions`, `reporter`), hosting approval (`hub/host/*`), routing of posts and streams with cancel,
  `context.service` and `context.device` selection, the `counter`, `random`, `first` and `available` balancers,
  waiting requests and `hub/balancer/limit`
- `default-deny`/`default-allow` with every built-in API classified, grants (`hub/grant*`, the old `hub/call/*`
  on top of them), groups (`hub/group/*`, `hub/groups`, several groups per member, person groups, `owners`)
- device certificates, `devices.json`, pending devices with safety codes, approve, rename, remove, revoke (with
  tombstones and revoked keys), the reporter role, `hub/device/describe` (with signed SSH host keys) and live data
- `hub/api`, `hub/api/services`, `hub/status`, `hub/status/badges`, `hub/connections`, `hub/header`,
  `hub/profile/update`, `hub/key`, `hub/security/mode*`
- pairing (`hub/pair`, `hub/pair/new`, `--pair`; at least 1 s per check, one check at a time, 10 wrong codes
  invalidate the code) and local mode
- corrupt stores are moved aside; a corrupt `hub.json`, `paths.json`, `whitelist.json`, `group-members.json`,
  `grants.json` or `devices.json` locks the hub down to owners until an owner sets the mode

## Hub Network

The network control plane of hub-server (`src/network/*`, protocol.md section 10), with the same wire format and
signatures (checked against hub-server's vectors and a Go-signed admission):

- `hub/net/bind` with the `machine` (proof from this host's agent socket), `apple-app` (owners) and `join`
  (inviter-signed admission) kinds; members keyed `device:<id>`, one endpoint per device, endpoint replacement after a
  reinstall; overlay addresses from `100.96.0.0/11` and `fd48:5542:4e45::/48`, released a day after a member leaves
- shares (`network/shares/*`, `canonicalAuthority`, `share_device_mismatch`), share policies as grants, resource
  generations, hub-signed connection grants, rendezvous tickets and gateway grants
- `network/agents/list` with `member`, `device` and `deviceAuthority`, `network/devices/revoked` with WireGuard keys,
  `hub/net/node` (`null` until set), `hub/net/list`, `hub/net/local-agent`, `hub/net/apple-agent/*`, owner-only test routes
- `hub/devices` shows each device's `network` state and `overlay` address

The `machine` agent proves itself over `/var/run/hub-net/agent.sock` (macOS) or `/run/hub-net/agent.sock` (Linux);
`localAgentEndpoint` (`--net-agent`, `HUB_NET_AGENT_SOCKET`) picks another socket or `tcp://host:port`, for an agent
that runs next to the hub in a container. On iOS there is no machine agent: the app's packet tunnel binds as
`apple-app`.

## Not implemented

- Merging and proxies (`hub/merge/add|remove`, `hub/proxy*`, `--merge`, `--proxy`). `hub/merge/status` streams `[]`.
- The Apple local network agent APIs.
- Migration of the pre-grants stores (`clients.json`, path lists in `groups.json`, `group_users.json`): a data
  directory from an old hub-pro should go through hub-server once first.

## Tests

```sh
swift test                      # JSON, WebSocket, peer, vectors (Docs/Devices/vectors.json), security, pairing, an in-process hub
swift build --product channel-fixture && bun test Tests/interop    # the channel TS client against ChannelServer
Scripts/conformance.sh          # Core/hub-server's raw-protocol harness against hub-server-swift
Scripts/sdk-live.sh             # the TS SDK and the Swift SDK's live suites against hub-server-swift
```

Built for devices with `xcodebuild -scheme HubServer -destination 'generic/platform=iOS' build` (and macOS,
visionOS, tvOS).

## Why ChannelServer isn't in ChannelSwift

ChannelSwift is a client built around Codable types and the main actor, and is frozen. A hub routes messages it
doesn't know the types of, passes structured errors through unchanged and must not run on the main actor of the app
that embeds it, so the server side uses a JSON value type and a serial queue instead. It lives here as its own
product; moving it into the Channel folder later is a rename.
