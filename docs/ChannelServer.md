# ChannelServer

## Purpose

`ChannelServer` is the server side of the [channel](https://github.com/v57/channel) protocol in Swift: a JSON value
type, a WebSocket server on a plain TCP listener, a symmetric channel peer, a router that dispatches posts, streams
and subscriptions by path, and a QUIC transport on Apple platforms. [HubServer](HubServer.md) is built on it, and
`import HubServer` re-exports it.

Use it to serve channel clients from Swift without a hub. It is not a channel client library with Codable types: that
is ChannelSwift, which is built around the main actor. ChannelServer routes messages whose types it doesn't know,
passes errors through unchanged, and runs on a serial queue you give it.

## Getting started

```swift
// Package.swift
dependencies: [
  .package(url: "https://github.com/v57/HubServer.git", branch: "main"),
],
targets: [
  .target(name: "MyServer", dependencies: [.product(name: "ChannelServer", package: "HubServer")]),
]
```

```swift
import ChannelServer
import Foundation

let queue = DispatchQueue(label: "server")
let router = ChannelRouter()
router
  .post("hello") { _ in "world" }
  .stream("count") { stream in
    for number in 0..<3 { stream.send(.int(number)) }
    stream.finish()
  }
router.listen(WebSocketServer(ListenAddress(host: "127.0.0.1", port: 2049)), queue: queue) { result in
  print("listening:", result)
}
dispatchMain()
```

A channel client then connects to `ws://127.0.0.1:2049`, posts `hello` and streams `count`.
`Sources/channel-fixture/main.swift` serves the routes of channel's own test server and shows the rest of the API in
use.

## Main API

Everything runs on the queue passed to `listen`; handlers are called there and must not block it.

### Routing

| | |
|---|---|
| `ChannelRouter()` | A server |
| `post(_ path:, _ handler: (IncomingCall) throws -> JSON?)` | A post answered with the handler's result |
| `post(_ path:, answering: (IncomingCall) throws -> Void)` | A post the handler answers itself, later if it wants (`call.respond`, `call.fail`, `call.finish`) |
| `stream(_ path:, _ handler: (IncomingStream) throws -> Void)` | A stream: `send(_:)` values, then `finish()` or `fail(_:)`; `onCancel` when the client leaves |
| `postOther`, `streamOther` | Handlers for paths without a route of their own |
| `sub(_ path:, _ handler: (IncomingSubscription) throws -> (topic: String?, body: JSON?))` | A subscription: the topic to join and a snapshot |
| `publish(_ topic:, _ body:)` | Sends an event to every peer subscribed to the topic |
| `check` | Runs before every handler, like channel TS middleware; throwing answers with the error |
| `onConnect`, `onDisconnect`, `peers` | Connected peers |
| `listen(_ transport:, queue:, state:, ready:)` | Serves on a transport. `state` makes a connection's state from its `UpgradeRequest` (throwing refuses it); `ready` gets the port |
| `stop()` | Stops every transport and closes every connection |

`IncomingCall`, `IncomingStream` and `IncomingSubscription` carry `path`, `body`, `context` and a weak `peer`. A thrown
error answers the call: a `ChannelFailure(message, code:, info:)` as it is, any other error by its description.
`ChannelFailure.apiNotFound`, `.subscriptionNotFound`, `.cancelled` and `.disconnected` are the protocol's own.

### Peers

`ChannelPeer` is one connection. Channel is symmetric, so a server can call its client too: `request(_:body:context:
response:)` and `stream(_:body:context:event:)` return an id for `cancel(_:)`. `state` holds what `listen`'s `state`
closure made. One connection may have at most `ChannelPeer.maxOpenRequests` (256) calls and streams open.

### Transports

| | |
|---|---|
| `ChannelTransport` | What `listen` takes: a server of message connections |
| `WebSocketServer(_ address:, options:)` | WebSocket on this platform's TCP listener. `Options`: `maxPayload` (16 MiB), `idleTimeout` (120 s) |
| `WebSocketServer(listener:options:)` | WebSocket on any `ByteStreamListener` |
| `ByteStreamListener`, `makeByteStreamListener(_:)` | Plain TCP: `NetworkStreamListener` (Network.framework) on Apple platforms, `SocketStreamListener` (POSIX sockets) where Network.framework is missing |
| `QUICServer(_ address:, identity:, options:)`, `QUICServer(_:pkcs12:password:options:)` | Channel over QUIC (ALPN `channel/1`), Apple platforms. The PKCS#12 initializer keeps the key in memory, which needs macOS 15 / iOS 18; before that it throws, so pass a `SecIdentity` |
| `ListenAddress(port:)`, `ListenAddress(host:port:)`, `ListenAddress("127.0.0.1:1997")` | Where to listen; port 0 picks a free one |
| `UpgradeRequest` | The connection's method, path, query, headers and remote address; `channelHeaders` merges them the way channel servers read headers |

The QUIC wire format is channel's `docs/quic.md`. Run a `QUICServer` next to a `WebSocketServer` on the same router:
browsers and most ports speak WebSocket only. Network.framework takes one QUIC connection per client address and
port, so a client dials each connection from its own UDP socket.

### JSON

`JSON` is an enum (`null`, `bool`, `int`, `double`, `string`, `array`, `object`) with literals, accessors (`string`,
`int`, `bool`, `array`, `object`, subscripts) and `JSON.parse(_:)` / `text`. `JSONObject` keeps key order.

## Platform notes

| Platform | |
|---|---|
| macOS 13, iOS 16, tvOS 16, visionOS 1, Mac Catalyst 16 | Network.framework TCP and QUIC |
| Linux | WebSocket on POSIX sockets; no QUIC |
| Windows, Android | Not yet: no TCP listener. A port can bring its own `ByteStreamListener` or `ChannelTransport` |

## Testing

```sh
swift test --filter ChannelServerTests     # JSON, WebSocket framing, the peer
swift build --product channel-fixture && bun test Tests/interop   # channel's TS client against the fixture
```

The interop tests import the channel TS client from `../../Channel/channel` (the Hub workspace layout).
`channel-fixture` listens on `CHANNEL_TEST_PORT` (2049 by default), and also over QUIC with `CHANNEL_QUIC_P12` and
`CHANNEL_QUIC_PASSWORD`.
