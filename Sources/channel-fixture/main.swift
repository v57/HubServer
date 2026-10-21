// The routes of Channel/channel/tests/server.ts, served by ChannelServer, for Tests/interop/channel-interop.ts
// Run: swift run channel-fixture [port]   (CHANNEL_TEST_PORT or 2049)
import ChannelServer
import Foundation

final class State {
  var name: String?
  let headers: [String: String]
  init(headers: [String: String]) { self.headers = headers }
}

setvbuf(stdout, nil, _IOLBF, 0)
let queue = DispatchQueue(label: "channel-fixture")
let arguments = CommandLine.arguments.dropFirst()
let port = UInt16(arguments.first ?? ProcessInfo.processInfo.environment["CHANNEL_TEST_PORT"] ?? "2049") ?? 2049
let router = ChannelRouter()
var stats: [String: Int] = ["cancels": 0, "streamCancel": 0, "drops": 0, "rooms": 0, "once": 0]

func state(_ peer: ChannelPeer) -> State { peer.state as! State }
func after(_ seconds: Double, _ action: @escaping () -> Void) {
  queue.asyncAfter(deadline: .now() + seconds, execute: action)
}

/// Sends `count` numbers, one per millisecond, until the stream is cancelled
func numbers(_ stream: IncomingStream, count: Int, counter: String? = nil) {
  var index = 0
  func next() {
    guard !stream.isFinished else { return }
    guard index < count else { return stream.finish() }
    stream.send(.int(index))
    index += 1
    after(0.001) {
      if let counter, !stream.isFinished { stats[counter, default: 0] += 1 }
      next()
    }
  }
  next()
}

/// Streams the client's own stream back to it
func mirror(_ stream: IncomingStream, path: String) {
  let peer = stream.peer
  let id = peer.stream(path) { event in
    switch event {
    case .value(let value): stream.send(value)
    case .done: stream.finish()
    case .failure(let failure): stream.fail(failure)
    }
  }
  stream.onCancel { peer.cancel(id) }
}

router
  .post("hello") { _ in "world" }
  .post("mirror", answering: { call in
    call.peer.request("hello") { call.finish($0.mapError { $0 as Error }) }
  })
  .post("echo") { $0.body }
  .post("empty") { _ in nil }
  .post("slow", answering: { call in after(0.05) { call.respond("slow") } })
  .post("disconnect") { call in
    call.peer.close()
    return nil
  }
  .post("auth") { call in
    state(call.peer).name = call.body?["name"]?.string
    return JSON(state(call.peer).name)
  }
  .post("auth/name") { call in
    guard let name = state(call.peer).name else { throw ChannelFailure("unauthorized") }
    return .string(name)
  }
  .stream("stream/values") { numbers($0, count: 3) }
  .stream("stream/cancel") { numbers($0, count: 10, counter: "streamCancel") }
  .stream("mirror/stream") { mirror($0, path: "stream/values") }
  .stream("mirror/stream/cancel") { mirror($0, path: "stream/cancel") }
  .post("v2/error") { _ -> JSON? in throw ChannelFailure("banned", code: 403, info: ["remaining": 5]) }
  .post("v2/error/code") { _ -> JSON? in throw ChannelFailure("slow down", code: "rate_limited", info: ["retryAfter": 1]) }
  .post("v2/never", answering: { call in call.onCancel { stats["cancels", default: 0] += 1 } })
  .post("v2/drop", answering: { call in
    stats["drops", default: 0] += 1
    call.peer.close()
  })
  .post("v2/drops") { _ in .int(stats["drops"] ?? 0) }
  .post("v2/drops/reset") { _ in
    stats["drops"] = 0
    return nil
  }
  .post("v2/headers") { call in
    .object(JSONObject(state(call.peer).headers.sorted { $0.key < $1.key }.map { ($0.key, JSON.string($0.value)) }))
  }
  .sub("v2/room") { call in
    stats["rooms", default: 0] += 1
    guard let room = call.body?["room"]?.string else { throw ChannelFailure("room required") }
    return ("room/" + room, "joined")
  }
  .post("v2/publish") { call in
    router.publish("room/" + (call.body?["room"]?.string ?? ""), call.body?["body"])
    return .null
  }
  .sub("v2/once") { _ in
    stats["once", default: 0] += 1
    return (nil, "once")
  }
  .sub("v2/private") { call in
    guard let name = state(call.peer).name else { throw ChannelFailure("unauthorized", code: 401) }
    return ("private/" + name, .string(name))
  }
  // Not in server.ts: the counters the TS tests read from `stats` in-process
  .post("fixture/stats") { _ in .object(JSONObject(stats.sorted { $0.key < $1.key }.map { ($0.key, JSON.int($0.value)) })) }

queue.async {
  router.listen(WebSocketServer(ListenAddress(host: "127.0.0.1", port: port)), queue: queue, state: { request in
    State(headers: request.channelHeaders)
  }) { result in
    switch result {
    case .success(let port): print("listening on \(port)")
    case .failure(let error):
      print("listen failed: \(error)")
      exit(1)
    }
  }
}
dispatchMain()
