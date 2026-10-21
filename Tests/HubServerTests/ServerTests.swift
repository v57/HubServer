import Foundation
import XCTest
@testable import HubServer

/// A channel client on URLSessionWebSocketTask: posts and streams, and answers the hub's calls with `handlers`
final class TestClient: @unchecked Sendable {
  private let task: URLSessionWebSocketTask
  private let lock = NSLock()
  private var nextId = 0
  private var waiting: [Int: (JSON) -> Void] = [:]
  var handlers: [String: (JSON) -> JSON] = [:]
  /// Handlers that answer later through the callback
  var answering: [String: (JSON, @escaping (JSON) -> Void) -> Void] = [:]
  /// Contexts the handlers were called with
  var contexts: [JSON] = []

  init(port: UInt16, headers: [String: String] = [:]) {
    var request = URLRequest(url: URL(string: "ws://127.0.0.1:\(port)")!)
    for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
    task = URLSession.shared.webSocketTask(with: request)
    task.resume()
    receive()
  }

  private func receive() {
    task.receive { [weak self] result in
      guard let self, case .success(.string(let text)) = result, let message = try? JSON.parse(text) else { return }
      if let path = message["path"]?.string, let id = message["id"]?.int {
        lock.withLock { self.contexts.append(message["context"] ?? .null) }
        if let handler = answering[path] {
          handler(message["body"] ?? .null) { [self] body in self.send(["id": .int(id), "body": body]) }
        } else {
          let body = handlers[path]?(message["body"] ?? .null) ?? .null
          send(["id": .int(id), "body": body])
        }
      } else if let id = message["id"]?.int {
        let handler = lock.withLock { self.waiting[id] }
        handler?(message)
      }
      receive()
    }
  }

  private func send(_ message: JSON) {
    task.send(.string(message.text)) { _ in }
  }

  private func makeId(_ handler: @escaping (JSON) -> Void) -> Int {
    lock.withLock {
      nextId += 1
      waiting[nextId] = handler
      return nextId
    }
  }

  func post(_ path: String, _ body: JSON? = nil, context: JSON? = nil, timeout: TimeInterval = 5) async throws -> JSON? {
    try await withCheckedThrowingContinuation { continuation in
      let once = Once()
      let id = makeId { message in
        guard once.claim() else { return }
        if let error = message["error"]?.string {
          continuation.resume(throwing: ChannelFailure(error, code: message["code"]))
        } else {
          continuation.resume(returning: message["body"])
        }
      }
      var request: JSONObject = ["id": .int(id), "path": .string(path)]
      if let body { request["body"] = body }
      if let context { request["context"] = context }
      send(.object(request))
      DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
        if once.claim() { continuation.resume(throwing: ChannelFailure("timeout")) }
      }
    }
  }

  /// The first `count` values of a stream, then cancels it
  func values(_ path: String, _ body: JSON? = nil, count: Int = 1, timeout: TimeInterval = 5) async throws -> [JSON] {
    try await withCheckedThrowingContinuation { continuation in
      let once = Once()
      var values: [JSON] = []
      var id = 0
      id = makeId { [self] message in
        if let error = message["error"]?.string {
          if once.claim() { continuation.resume(throwing: ChannelFailure(error)) }
          return
        }
        if message["done"] == .bool(true) {
          if once.claim() { continuation.resume(returning: values) }
          return
        }
        values.append(message["body"] ?? .null)
        if values.count == count, once.claim() {
          send(["cancel": .int(id)])
          continuation.resume(returning: values)
        }
      }
      var request: JSONObject = ["id": .int(id), "stream": .string(path)]
      if let body { request["body"] = body }
      send(.object(request))
      DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
        if once.claim() { continuation.resume(throwing: ChannelFailure("timeout")) }
      }
    }
  }

  func close() {
    task.cancel(with: .normalClosure, reason: nil)
  }
}

final class Once: @unchecked Sendable {
  private let lock = NSLock()
  private var done = false
  func claim() -> Bool {
    lock.withLock {
      defer { done = true }
      return !done
    }
  }
}

final class ServerTests: XCTestCase {
  func auth(_ key: HubKeyPair, hubKey: String) -> [String: String] {
    let expiry = Int(Date().timeIntervalSince1970) + 60
    return ["v": "1", "auth": "key.\(key.publicKey).\(key.sign("hub1:\(hubKey):\(expiry)")).\(expiry)"]
  }
  func certificate(device: HubKeyPair, service: HubKeyPair, instance: String) -> String {
    let now = Int(Date().timeIntervalSince1970)
    let json: JSON = ["v": 1, "device": .string(device.publicKey), "service": .string(service.publicKey), "instance": .string(instance),
                      "deviceName": "Test Mac", "platform": "macos", "iat": .int(now), "exp": .int(now + 3600)]
    let payload = HubCrypto.base64URLEncode(json.data)
    return "\(payload).\(device.sign(payload))"
  }

  func testRoutingThroughTheHub() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let owner = HubKeyPair(), service = HubKeyPair(), device = HubKeyPair(), stranger = HubKeyPair()
    var configuration = HubServer.Configuration(dataDirectory: directory)
    configuration.listen = ListenAddress(host: "127.0.0.1", port: 0)
    configuration.owners = [owner.publicKey]
    configuration.log = { _ in }
    let server = HubServer(configuration)
    let port = try await server.start()
    let hubKey = try XCTUnwrap(server.status.hubKey)
    XCTAssertEqual(server.status.state, .running)
    XCTAssertNil(server.status.pairingCode)

    let anonymous = TestClient(port: port)
    let info = try await anonymous.post("hub/info")
    XCTAssertEqual(info?["key"]?.string, hubKey)
    XCTAssertEqual(info?["mode"], "default-deny")

    // A device-certified service asks to host a path; the owner approves hosting and the device
    let provider = TestClient(port: port, headers: auth(service, hubKey: hubKey).merging(["device": certificate(device: device, service: service, instance: "test/echo")]) { $1 })
    provider.handlers["test/echo"] = { body in body }
    _ = try await provider.post("hub/service/update", ["services": [["path": "test/echo"]], "reporter": true])
    let ownerClient = TestClient(port: port, headers: auth(owner, hubKey: hubKey))
    let pending = try await ownerClient.values("hub/devices/pending")
    XCTAssertEqual(pending.first?.array?.first?["id"]?.string, HubCrypto.deviceId(spki: device.publicKey))
    _ = try await ownerClient.post("hub/host/update", ["key": .string(service.publicKey), "allow": ["test/echo"]])
    _ = try await ownerClient.post("hub/device/approve", ["id": .string(HubCrypto.deviceId(spki: device.publicKey))])

    // The owner's call reaches the service with the caller in the context, a forged one replaced
    let echoed = try await ownerClient.post("test/echo", "hello", context: ["hub": ["caller": ["owner": false]], "trace": 1])
    XCTAssertEqual(echoed, "hello")
    let context = try XCTUnwrap(provider.contexts.last)
    XCTAssertEqual(context["trace"], 1)
    XCTAssertEqual(context["hub"]?["hubKey"]?.string, hubKey)
    XCTAssertEqual(context["hub"]?["caller"]?["key"]?.string, owner.publicKey)
    XCTAssertEqual(context["hub"]?["caller"]?["owner"], true)

    // Selection by device
    let selected = try await ownerClient.post("test/echo", 1, context: ["device": .string(HubCrypto.deviceId(spki: device.publicKey))])
    XCTAssertEqual(selected, 1)
    do {
      _ = try await ownerClient.post("test/echo", 1, context: ["device": .string(String(repeating: "0", count: 32))])
      XCTFail("selected a missing device")
    } catch {
      XCTAssertEqual((error as? ChannelFailure)?.message, "api not found")
    }

    // Default deny, then a grant
    let strangerClient = TestClient(port: port, headers: auth(stranger, hubKey: hubKey))
    do {
      _ = try await strangerClient.post("test/echo", 1)
      XCTFail("stranger allowed")
    } catch {
      XCTAssertEqual((error as? ChannelFailure)?.message, "permissions required")
    }
    _ = try await ownerClient.post("hub/grant/add", ["subject": ["key": .string(stranger.publicKey)], "object": ["prefix": "test/"]])
    let granted = try await strangerClient.post("test/echo", 2)
    XCTAssertEqual(granted, 2)
    let api = try await strangerClient.post("hub/api")
    XCTAssertTrue(api?.strings?.contains("test/echo") == true)
    XCTAssertFalse(api?.strings?.contains("hub/connections") == true)

    // Devices list the service, the reporter describes its device
    _ = try await provider.post("hub/device/describe", ["os": "27.0", "arch": "arm64"])
    do {
      _ = try await strangerClient.post("hub/device/data", ["cpu": 1])
      XCTFail("a stranger reported")
    } catch {
      XCTAssertEqual((error as? ChannelFailure)?.message, "not the device reporter")
    }
    let devices = try await ownerClient.values("hub/devices")
    let listed = try XCTUnwrap(devices.first?.array?.first { $0["id"]?.string == HubCrypto.deviceId(spki: device.publicKey) })
    XCTAssertEqual(listed["os"], "27.0")
    XCTAssertEqual(listed["services"]?.array?.first?["instance"], "test/echo")
    XCTAssertEqual(listed["services"]?.array?.first?["paths"], ["test/echo"])

    // Revoking the device closes the service, its key is refused afterwards
    _ = try await ownerClient.post("hub/device/revoke", ["id": .string(HubCrypto.deviceId(spki: device.publicKey))])
    let refused = TestClient(port: port, headers: auth(service, hubKey: hubKey))
    do {
      _ = try await refused.post("hub/info", timeout: 2)
      XCTFail("revoked key connected")
    } catch {}

    // Restarting keeps the key, owners and tombstone
    await server.stop()
    XCTAssertEqual(server.status.state, .stopped)
    let again = HubServer(configuration)
    let newPort = try await again.start()
    XCTAssertEqual(again.status.hubKey, hubKey)
    let ownerAgain = TestClient(port: newPort, headers: auth(owner, hubKey: hubKey))
    let mode = try await ownerAgain.values("hub/security/mode")
    XCTAssertEqual(mode.first?["mode"], "default-deny")
    let afterRestart = try await ownerAgain.values("hub/devices")
    XCTAssertEqual(afterRestart.first?.array?.first { $0["id"]?.string == HubCrypto.deviceId(spki: device.publicKey) }?["revoked"], true)
    await again.stop()
    for client in [anonymous, provider, ownerClient, strangerClient, refused, ownerAgain] { client.close() }
  }

  func testPairingThroughTheServer() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    var configuration = HubServer.Configuration(dataDirectory: directory)
    configuration.listen = ListenAddress(host: "127.0.0.1", port: 0)
    configuration.log = { _ in }
    let server = HubServer(configuration)
    let port = try await server.start()
    let code = try XCTUnwrap(server.status.pairingCode)
    let hubKey = try XCTUnwrap(server.status.hubKey)
    let key = HubKeyPair()
    let client = TestClient(port: port, headers: auth(key, hubKey: hubKey))
    let result = try await client.post("hub/pair", ["code": .string(code.code)])
    XCTAssertEqual(result?["owner"], true)
    XCTAssertEqual(result?["hubKey"]?.string, hubKey)
    let connections = try await client.values("hub/connections")
    XCTAssertEqual(connections.first?.array?.count, 1)
    try await Task.sleep(nanoseconds: 200_000_000)
    XCTAssertEqual(server.status.owners, 1)
    XCTAssertNil(server.status.pairingCode)
    let newCode = try await client.post("hub/pair/new")
    XCTAssertNotNil(newCode?["code"]?.string)
    let link = HubServer.pairingLink(address: "ws://mac.local:1997", code: newCode!["code"]!.string!)
    XCTAssertEqual(link.absoluteString, "hub://pair?a=ws://mac.local:1997&c=\(newCode!["code"]!.string!)")
    await server.stop()
    client.close()
  }

  func testLocalMode() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let launcher = HubKeyPair()
    var configuration = HubServer.Configuration(dataDirectory: directory)
    configuration.listen = ListenAddress(port: 0)
    configuration.local = true
    configuration.launcherKey = launcher.publicKey
    configuration.log = { _ in }
    let server = HubServer(configuration)
    let port = try await server.start()
    XCTAssertNil(server.status.pairingCode)
    let client = TestClient(port: port, headers: auth(launcher, hubKey: server.status.hubKey!))
    let info = try await client.post("hub/info")
    XCTAssertEqual(info?["mode"], "default-allow")
    // The launcher is an owner without being stored
    let connections = try await client.values("hub/connections")
    XCTAssertEqual(connections.count, 1)
    XCTAssertEqual(server.status.owners, 0)
    await server.stop()
    client.close()
  }
}

/// hub-server's test/network-hub.test.ts
final class NetworkServerTests: XCTestCase {
  func testNetworkOnTheHub() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let owner = HubKeyPair(), lostDevice = HubKeyPair(), otherDevice = HubKeyPair()
    var configuration = HubServer.Configuration(dataDirectory: directory)
    configuration.listen = ListenAddress(host: "127.0.0.1", port: 0)
    configuration.owners = [owner.publicKey, lostDevice.publicKey, otherDevice.publicKey]
    configuration.log = { _ in }
    let server = HubServer(configuration)
    let port = try await server.start()
    let hubKey = server.status.hubKey!
    let helper = ServerTests()
    let owners = TestClient(port: port, headers: helper.auth(owner, hubKey: hubKey))

    // There is no built-in node
    let node = try await owners.values("hub/net/node")
    XCTAssertEqual(node, [.null])
    _ = try await owners.post("hub/net/node/set", "node.example:443")
    let set = try await owners.values("hub/net/node")
    XCTAssertEqual(set, ["node.example:443"])
    _ = try await owners.post("hub/net/node/set", .null)

    // Revoking a device removes its member and tells the other agents
    func agent(_ device: HubKeyPair, name: String) -> TestClient {
      let key = HubKeyPair()
      var headers = helper.auth(key, hubKey: hubKey)
      headers["device"] = helper.certificate(device: device, service: key, instance: name)
      return TestClient(port: port, headers: headers)
    }
    let bind: (String) -> JSON = { ["version": 1, "bindingKind": "apple-app", "wireGuardKey": .string($0), "overlayAddresses": [],
      "connectedAt": .string(isoNow()), "name": "Agent Box"] }
    let lost = agent(lostDevice, name: "lost")
    let other = agent(otherDevice, name: "other")
    let lostBound = try await lost.post("hub/net/bind", bind("wg-lost"))
    XCTAssertEqual(lostBound?["profile"]?["overlayAddresses"]?.array?.count, 2)
    _ = try await other.post("hub/net/bind", bind("wg-other"))
    let lostId = HubCrypto.deviceId(spki: lostDevice.publicKey)
    try await Task.sleep(nanoseconds: 300_000_000)
    let devices = try await owners.values("hub/devices")
    let listed = try XCTUnwrap(devices[0].array?.first { $0["id"]?.string == lostId })
    XCTAssertEqual(listed["network"], "online")
    XCTAssertTrue(listed["overlay"]?["address"]?.string?.hasPrefix("100.") == true)
    XCTAssertNotNil(listed["overlay"]?["authority"]?.string?.range(of: "^test-mac-[a-z2-7]{16}\\.v1-[a-z2-7]{16}\\.hub\\.invalid$", options: .regularExpression))
    _ = try await owners.post("hub/device/revoke", ["id": .string(lostId)])
    try await Task.sleep(nanoseconds: 200_000_000)
    let revoked = try await other.values("network/devices/revoked")
    XCTAssertEqual(revoked[0].array?.first?["device"]?.string, lostId)
    XCTAssertEqual(revoked[0].array?.first?["wireGuardKeys"], ["wg-lost"])
    let members = try await other.values("network/agents/list")
    XCTAssertFalse(members[0].array!.contains { $0["wireGuardKey"] == "wg-lost" })
    XCTAssertTrue(members[0].array!.contains { $0["wireGuardKey"] == "wg-other" })

    // Test routes are owner-only
    let user = TestClient(port: port, headers: helper.auth(HubKeyPair(), hubKey: hubKey))
    do {
      _ = try await user.post("hub/net/test/complete", "ok")
      XCTFail("a user reached a test route")
    } catch {
      XCTAssertEqual((error as? ChannelFailure)?.message, "permissions required")
    }
    // Other Hub Network APIs answer instead of `api not found`
    let resources = try await owners.values("network/resource/list")
    XCTAssertEqual(resources, [[]])
    await server.stop()
    for client in [owners, lost, other, user] { client.close() }
  }
}

/// hub-server's test/pending.test.ts: calls that arrive before a provider is available
final class PendingTests: XCTestCase {
  var server: HubServer!
  var port: UInt16 = 0
  var hubKey = ""
  var caller: TestClient!
  var clients: [TestClient] = []
  let helper = ServerTests()

  override func setUp() async throws {
    let owner = HubKeyPair()
    var configuration = HubServer.Configuration(dataDirectory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
    configuration.listen = ListenAddress(host: "127.0.0.1", port: 0)
    configuration.owners = [owner.publicKey]
    configuration.log = { _ in }
    server = HubServer(configuration)
    port = try await server.start()
    hubKey = server.status.hubKey!
    caller = TestClient(port: port, headers: helper.auth(owner, hubKey: hubKey))
    clients = [caller]
  }

  override func tearDown() async throws {
    ServiceGroup.waitTimeout = 30
    for client in clients { client.close() }
    await server.stop()
  }

  /// A provider of `path`; hosting needs approval (`hub/host/update`) unless `approved`
  func provider(_ path: String, approved: Bool = true, limit: Int? = nil, handler: @escaping (JSON) -> JSON = { $0 }) async throws -> (key: HubKeyPair, client: TestClient) {
    let key = HubKeyPair()
    let client = TestClient(port: port, headers: helper.auth(key, hubKey: hubKey))
    clients.append(client)
    client.handlers[path] = handler
    var header: JSONObject = ["path": .string(path)]
    if let limit { header["limit"] = .int(limit) }
    _ = try await client.post("hub/service/update", ["services": [.object(header)]])
    if approved { _ = try await caller.post("hub/host/update", ["key": .string(key.publicKey), "allow": [.string(path)]]) }
    return (key, client)
  }

  /// How many calls of the path wait
  func pending(_ path: String) async throws -> Int {
    let status = try await caller.values("hub/status")
    return status[0]["services"]?.array?.first { $0["name"]?.string == path }?["pending"]?.int ?? 0
  }

  func until(_ check: () async throws -> Bool, timeout: TimeInterval = 5) async throws {
    let end = Date().addingTimeInterval(timeout)
    while try await !check() {
      guard Date() < end else { throw ChannelFailure("timed out") }
      try await Task.sleep(nanoseconds: 20_000_000)
    }
  }

  /// Calls in this order: each one is on the wire before the next starts
  func sendAll(_ path: String, _ bodies: [JSON]) async throws -> [Task<String, Never>] {
    var calls: [Task<String, Never>] = []
    for body in bodies {
      calls.append(send(path, body))
      try await Task.sleep(nanoseconds: 30_000_000)
    }
    return calls
  }

  func send(_ path: String, _ body: JSON, timeout: TimeInterval = 10) -> Task<String, Never> {
    let caller = self.caller!
    return Task {
      do {
        let result = try await caller.post(path, body, timeout: timeout)
        return result?.string ?? result?.text ?? "nil"
      } catch {
        return "error: \(error)"
      }
    }
  }

  func testACallMadeBeforeHostingIsApprovedRunsOnceItIs() async throws {
    let unapproved = try await provider("pending/approve", approved: false) { .string("echo \($0.text)") }
    let calls = try await sendAll("pending/approve", (1...5).map { .int($0) })
    try await until { try await self.pending("pending/approve") == 5 }
    _ = try await caller.post("hub/host/update", ["key": .string(unapproved.key.publicKey), "allow": ["pending/approve"]])
    var results: [String] = []
    for call in calls { results.append(await call.value) }
    XCTAssertEqual(results, ["echo 1", "echo 2", "echo 3", "echo 4", "echo 5"])
    let waiting = try await pending("pending/approve")
    XCTAssertEqual(waiting, 0)
    let later = await send("pending/approve", 6).value
    XCTAssertEqual(later, "echo 6")
  }

  func testACallMadeWhileNoProviderIsConnectedRunsWhenOneRegisters() async throws {
    let first = try await provider("pending/late")
    first.client.close()
    try await until {
      let status = try await self.caller.values("hub/status")
      return status[0]["services"]?.array?.first { $0["name"]?.string == "pending/late" }?["services"]?.int == 0
    }
    let calls = try await sendAll("pending/late", ["a", "b", "c"])
    try await until { try await self.pending("pending/late") == 3 }
    _ = try await provider("pending/late") { .string(($0.string ?? "").uppercased()) }
    var results: [String] = []
    for call in calls { results.append(await call.value) }
    XCTAssertEqual(results, ["A", "B", "C"])
  }

  func testWaitingCallsRespectTheProviderLimitAndRunInOrder() async throws {
    let lock = NSLock()
    var running = 0, most = 0
    var order: [Int] = []
    var release: [() -> Void] = []
    let limited = try await provider("pending/limit", limit: 1)
    limited.client.answering["pending/limit"] = { body, answer in
      lock.withLock {
        running += 1
        most = max(most, running)
        order.append(body.int ?? -1)
        release.append {
          lock.withLock { running -= 1 }
          answer(body)
        }
      }
    }
    let calls = try await sendAll("pending/limit", (1...4).map { .int($0) })
    for index in 0..<4 {
      try await until { lock.withLock { release.count > index } }
      try await Task.sleep(nanoseconds: 50_000_000)
      XCTAssertEqual(lock.withLock { running }, 1)
      lock.withLock { release[index] }()
    }
    var results: [String] = []
    for call in calls { results.append(await call.value) }
    XCTAssertEqual(results, ["1", "2", "3", "4"])
    XCTAssertEqual(lock.withLock { order }, [1, 2, 3, 4])
    XCTAssertEqual(lock.withLock { most }, 1)
    // An idle provider serves a new call at once
    let late = send("pending/limit", 5)
    try await until { lock.withLock { release.count == 5 } }
    lock.withLock { release[4] }()
    let result = await late.value
    XCTAssertEqual(result, "5")
  }

  func testAWaitingCallFailsWithApiNotAvailableAfterTheTimeout() async throws {
    ServiceGroup.waitTimeout = 0.2
    _ = try await provider("pending/timeout", approved: false)
    let start = Date()
    let result = await send("pending/timeout", 1).value
    XCTAssertTrue(result.contains("api not available"), result)
    XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.19)
    let waiting = try await pending("pending/timeout")
    XCTAssertEqual(waiting, 0)
  }

  func testPendingLimitFailsTheOldestWaitingCalls() async throws {
    _ = try await caller.post("hub/balancer/limit", ["limit": 2])
    let unapproved = try await provider("pending/evict", approved: false)
    let calls = try await sendAll("pending/evict", (1...3).map { .int($0) })
    try await until { try await self.pending("pending/evict") == 2 }
    let oldest = await calls[0].value
    XCTAssertTrue(oldest.contains("api not available"), oldest)
    _ = try await caller.post("hub/host/update", ["key": .string(unapproved.key.publicKey), "allow": ["pending/evict"]])
    var results: [String] = []
    for call in calls.dropFirst() { results.append(await call.value) }
    XCTAssertEqual(results, ["2", "3"])
  }
}
