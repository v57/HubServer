import ChannelServer
import Foundation

// The hub host's own agent (hub-server's src/network/local-agent.ts): a `machine` agent proves it runs on the hub's
// host over the agent's local socket; an Apple app's packet tunnel binds as `apple-app` with short readiness leases.

enum LocalAgent {
  static let proofDomain = "hub-network/local-agent-binding/v1"
  static let bootstrapCapability = "invitation-bootstrap-v1"

  /// Where the hub reaches its host's agent: the agent's Unix socket, or `tcp://host:port` where the agent runs next
  /// to the hub in a container or VM and its socket is forwarded
  static var defaultEndpoint: String {
    #if os(Linux)
    "/run/hub-net/agent.sock"
    #else
    "/var/run/hub-net/agent.sock"
    #endif
  }

  /// The signed text of a binding proof
  static func proofInput(_ proof: JSON) -> Data {
    let capabilities = (proof["capabilities"]?.strings ?? []).sorted().joined(separator: ",")
    let lines = [proofDomain, String(proof["version"]?.int ?? 0), proof["key"]?.string ?? "", proof["connectionId"]?.string ?? "",
      proof["nonce"]?.string ?? "", capabilities, proof["issuedAt"]?.string ?? "", proof["expiresAt"]?.string ?? ""]
    return Data(lines.joined(separator: "\n").utf8)
  }

  static func validate(_ proof: JSON, key: String, connectionId: String, nonce: String, now: Date = Date()) throws {
    guard proof["version"]?.int == 1, proof["key"]?.string == key, proof["connectionId"]?.string == connectionId,
      proof["nonce"]?.string == nonce, !key.isEmpty, let capabilities = proof["capabilities"]?.strings,
      capabilities.contains(bootstrapCapability)
    else { throw ChannelFailure("invalid local agent binding proof") }
    guard let issuedAt = NetworkTime.parse(proof["issuedAt"]?.string), let expiresAt = NetworkTime.parse(proof["expiresAt"]?.string),
      issuedAt <= now.addingTimeInterval(30), expiresAt > now, expiresAt.timeIntervalSince(issuedAt) <= 60
    else { throw ChannelFailure("expired local agent binding proof") }
    guard let signature = proof["signature"]?.string.flatMap({ Data(base64Encoded: $0) }), let publicKey = HubCrypto.publicKey(spki: key),
      publicKey.isValidSignature(signature, for: proofInput(proof))
    else { throw ChannelFailure("invalid local agent binding proof signature") }
  }

  /// Asks the agent at `endpoint` to prove it holds `key`, for the connection `connectionId`. Blocking; call it off
  /// the hub's queue.
  static func prove(endpoint: String, key: String, connectionId: String, timeout: TimeInterval = 3) throws -> JSON {
    let nonce = HubCrypto.base64URLEncode(Data(HubCrypto.randomBytes(32)))
    let body: JSON = ["version": 1, "type": "binding-proof", "key": .string(key), "connectionId": .string(connectionId), "nonce": .string(nonce)]
    let proof = try post(endpoint: endpoint, path: "/binding/proof", body: body, timeout: timeout)
    try validate(proof, key: key, connectionId: connectionId, nonce: nonce)
    return proof
  }

  /// A minimal HTTP/1.1 POST over a Unix or TCP socket
  static func post(endpoint: String, path: String, body: JSON, timeout: TimeInterval) throws -> JSON {
    let descriptor = try connect(endpoint)
    defer { close(descriptor) }
    var interval = timeval(tv_sec: Int(timeout), tv_usec: 0)
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &interval, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &interval, socklen_t(MemoryLayout<timeval>.size))
    let payload = Array(body.text.utf8)
    let head = "POST \(path) HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: \(payload.count)\r\nConnection: close\r\n\r\n"
    let request = Array(head.utf8) + payload
    let total = request.count
    var sent = 0
    while sent < total {
      let offset = sent
      let count = request.withUnsafeBytes { send(descriptor, $0.baseAddress! + offset, total - offset, 0) }
      guard count > 0 else { throw ChannelFailure("local agent proof failed: send") }
      sent += count
    }
    var response: [UInt8] = []
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while response.count < 1024 * 1024 {
      let count = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress!, $0.count, 0) }
      if count <= 0 { break }
      response.append(contentsOf: buffer[..<count])
    }
    let text = String(decoding: response, as: UTF8.self)
    guard let separator = text.range(of: "\r\n\r\n") else { throw ChannelFailure("local agent proof failed: no response") }
    let status = Int(text.split(separator: " ", maxSplits: 2).dropFirst().first ?? "") ?? 0
    var content = String(text[separator.upperBound...])
    if text[..<separator.lowerBound].lowercased().contains("transfer-encoding: chunked") { content = dechunk(content) }
    guard (200..<300).contains(status) else { throw ChannelFailure("local agent proof failed: \(status) \(content)") }
    do {
      return try JSON.parse(content)
    } catch {
      throw ChannelFailure("local agent proof returned invalid JSON")
    }
  }

  private static func dechunk(_ text: String) -> String {
    var result = ""
    var rest = Substring(text)
    while let line = rest.range(of: "\r\n"), let size = Int(rest[..<line.lowerBound], radix: 16), size > 0 {
      let start = line.upperBound
      let utf8 = rest[start...].utf8
      let end = utf8.index(utf8.startIndex, offsetBy: min(size, utf8.count))
      result += String(rest[start..<end])
      rest = rest[end...].dropFirst(2)
    }
    return result
  }

  private static func connect(_ endpoint: String) throws -> Int32 {
    if endpoint.hasPrefix("tcp://") {
      let address = String(endpoint.dropFirst(6))
      guard let colon = address.lastIndex(of: ":"), let port = UInt16(address[address.index(after: colon)...]) else {
        throw ChannelFailure("invalid local agent endpoint")
      }
      let host = String(address[..<colon])
      var hints = addrinfo()
      hints.ai_socktype = streamSocket
      var info: UnsafeMutablePointer<addrinfo>?
      guard getaddrinfo(host, String(port), &hints, &info) == 0, let first = info else { throw ChannelFailure("local agent unreachable") }
      defer { freeaddrinfo(info) }
      let descriptor = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
      guard descriptor >= 0 else { throw ChannelFailure("local agent unreachable") }
      guard Foundation.connect(descriptor, first.pointee.ai_addr, first.pointee.ai_addrlen) == 0 else {
        close(descriptor)
        throw ChannelFailure("local agent unreachable")
      }
      return descriptor
    }
    let descriptor = socket(AF_UNIX, streamSocket, 0)
    guard descriptor >= 0 else { throw ChannelFailure("local agent unreachable") }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let path = Array(endpoint.utf8)
    guard path.count < MemoryLayout.size(ofValue: address.sun_path) else {
      close(descriptor)
      throw ChannelFailure("local agent socket path too long")
    }
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in
      for (index, byte) in path.enumerated() { buffer[index] = byte }
    }
    let result = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Foundation.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard result == 0 else {
      close(descriptor)
      throw ChannelFailure("local agent unreachable")
    }
    return descriptor
  }
}

/// The bound local agents: the persisted `machine` binding (`local-agent.json`) and the in-memory `apple-app` lease
final class LocalAgentBindings {
  struct Apple: Equatable {
    var key: String
    var capabilities: [String]
    var connectionId: String
    var wireGuardKey: String
    var hubNetworkId: String
    var tunnelInstanceId: String
    var generation: Int
    var expiresAt: String
  }
  /// `{ binding: { version, bindingKind, key, capabilities, boundAt }, pendingRebind: { key } }`
  private var data = JSONObject()
  private(set) var apple: Apple?
  /// Connections that bound, with the kind and key
  private var connected: [String: (kind: String, key: String)] = [:]
  private var lastError: String?
  let store: JSONStore
  var onAppleInvalidated: () -> Void = {}

  init(storage: Storage) {
    store = storage.store("local-agent.json")
    store.encode = { [unowned self] in .object(data) }
  }

  func load() {
    store.load { json in
      guard let object = json.object else { return }
      data = object
      if data["binding"]?["version"]?.int != 1 { data["binding"] = nil }
    }
  }

  var machine: (key: String, capabilities: [String])? {
    guard let binding = data["binding"], let key = binding["key"]?.string else { return nil }
    return (key, binding["capabilities"]?.strings ?? [])
  }

  /// After a proof from the agent: binds the machine agent, or refuses another key until an owner authorizes it
  func registerMachine(key: String, connectionId: String, proof: JSON) throws {
    guard proof["key"]?.string == key else { throw ChannelFailure("local_agent_proof_mismatch") }
    let current = machine
    let authorized = data["pendingRebind"]?["key"]?.string == key
    if let current, current.key != key, !authorized { throw ChannelFailure("local_agent_rebind_required") }
    if current == nil || current?.key != key {
      data["binding"] = ["version": 1, "key": .string(key), "capabilities": JSON((proof["capabilities"]?.strings ?? []).sorted()),
        "boundAt": .string(isoNow()), "bindingKind": "machine"]
      data["pendingRebind"] = nil
      store.writeNow()
    }
    connected[connectionId] = ("machine", key)
    lastError = nil
  }

  func failed(_ error: String) {
    lastError = error
  }

  func authorizeRebind(_ key: String?) throws {
    guard let key, !key.isEmpty else { throw ChannelFailure("invalid_local_agent_rebind") }
    data["pendingRebind"] = ["key": .string(key)]
    store.writeNow()
  }

  func bindApple(_ assertion: JSON, connectionId: String, key: String) throws {
    let wireGuardKey = assertion["wireGuardKey"]?.string ?? ""
    let hubNetworkId = assertion["hubNetworkId"]?.string ?? ""
    let tunnelInstanceId = assertion["tunnelInstanceId"]?.string ?? ""
    let generation = assertion["generation"]?.int ?? 0
    if let current = apple {
      let sameTunnel = current.connectionId == connectionId && current.key == key && current.wireGuardKey == wireGuardKey
        && current.hubNetworkId == hubNetworkId && current.tunnelInstanceId == tunnelInstanceId
      if sameTunnel, generation < current.generation { throw ChannelFailure("stale_apple_agent_generation") }
      // Generations only count inside one tunnel instance; a new instance replaces the old binding
      if !sameTunnel { invalidateApple() }
    }
    apple = Apple(key: key, capabilities: assertion["capabilities"]?.strings ?? [], connectionId: connectionId,
      wireGuardKey: wireGuardKey, hubNetworkId: hubNetworkId, tunnelInstanceId: tunnelInstanceId, generation: generation,
      expiresAt: assertion["expiresAt"]?.string ?? isoNow())
    connected[connectionId] = ("apple-app", key)
    lastError = nil
  }

  func renewApple(_ assertion: JSON, connectionId: String, key: String) throws {
    guard let current = apple, current.connectionId == connectionId, current.key == key,
      current.wireGuardKey == assertion["wireGuardKey"]?.string, current.hubNetworkId == assertion["hubNetworkId"]?.string,
      current.tunnelInstanceId == assertion["tunnelInstanceId"]?.string
    else { throw ChannelFailure("apple_agent_binding_mismatch") }
    if (assertion["generation"]?.int ?? 0) < current.generation { throw ChannelFailure("stale_apple_agent_generation") }
    try bindApple(assertion, connectionId: connectionId, key: key)
  }

  func unbindApple(_ request: JSON, connectionId: String) throws {
    guard let current = apple else { return }
    guard current.connectionId == connectionId, current.hubNetworkId == request["hubNetworkId"]?.string,
      current.tunnelInstanceId == request["tunnelInstanceId"]?.string, current.generation == request["generation"]?.int
    else { throw ChannelFailure("apple_agent_binding_mismatch") }
    invalidateApple()
  }

  func disconnect(_ connectionId: String) {
    connected[connectionId] = nil
    if apple?.connectionId == connectionId { invalidateApple() }
  }

  /// Drops an Apple lease that ran out
  func expireApple(now: Date = Date()) {
    guard let apple, (NetworkTime.parse(apple.expiresAt) ?? .distantPast) <= now else { return }
    invalidateApple()
  }

  private func invalidateApple() {
    guard let apple else { return }
    self.apple = nil
    connected[apple.connectionId] = nil
    onAppleInvalidated()
  }

  /// `hub/net/local-agent`
  func status() -> JSON {
    expireApple()
    let machine = self.machine
    let machineConnected = machine.map { machine in connected.values.contains { $0.kind == "machine" && $0.key == machine.key } } ?? false
    let appleConnected = apple.map { apple in
      connected[apple.connectionId]?.kind == "apple-app" && (NetworkTime.parse(apple.expiresAt) ?? .distantPast) > Date()
    } ?? false
    var object: JSONObject = ["version": 1]
    var capabilities: [String] = []
    var isConnected = false
    var bound = true
    if machineConnected, let machine {
      object["bindingKind"] = "machine"
      object["key"] = .string(machine.key)
      capabilities = machine.capabilities
      isConnected = true
    } else if appleConnected, let apple {
      object["bindingKind"] = "apple-app"
      object["key"] = .string(apple.key)
      object["tunnelInstanceId"] = .string(apple.tunnelInstanceId)
      object["generation"] = .int(apple.generation)
      object["expiresAt"] = .string(apple.expiresAt)
      capabilities = apple.capabilities
      isConnected = true
    } else if let machine {
      object["bindingKind"] = "machine"
      object["key"] = .string(machine.key)
      capabilities = machine.capabilities
    } else if let apple {
      object["bindingKind"] = "apple-app"
      object["key"] = .string(apple.key)
      object["tunnelInstanceId"] = .string(apple.tunnelInstanceId)
      object["generation"] = .int(apple.generation)
      object["expiresAt"] = .string(apple.expiresAt)
      capabilities = apple.capabilities
    } else {
      bound = false
    }
    let bootstrapCapable = capabilities.contains(LocalAgent.bootstrapCapability)
    let available = isConnected && bootstrapCapable
    var result: JSONObject = ["version": 1, "state": .string(!bound ? "unbound" : available ? "available" : "unavailable")]
    for (key, value) in object where key != "version" { result[key] = value }
    result["capabilities"] = JSON(capabilities)
    result["connected"] = .bool(isConnected)
    result["bootstrapCapable"] = .bool(bootstrapCapable)
    result["updatedAt"] = .string(isoNow())
    if !available {
      result["error"] = ["version": 1, "code": "local_agent_unavailable",
        "message": .string(lastError ?? (!bound ? "no local hub-net is bound" : "bound local hub-net is disconnected")), "retryable": true]
    }
    return .object(result)
  }
}

/// SOCK_STREAM as `socket` takes it: Glibc imports it as an enum
#if canImport(Glibc)
private let streamSocket = Int32(SOCK_STREAM.rawValue)
#else
private let streamSocket = SOCK_STREAM
#endif
