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
        let body = handlers[path]?(message["body"] ?? .null) ?? .null
        send(["id": .int(id), "body": body])
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
