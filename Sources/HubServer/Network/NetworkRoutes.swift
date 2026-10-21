import ChannelServer
import Foundation

/// Names of the Hub Network APIs for `hub/group/names`, as hub-server registers them
let networkAPINames: [(String, String)] = [
  ("network/shares/replace", "Hub Network: Manage Shares"), ("network/shares/published", "Hub Network: Manage Shares"),
  ("hub/net/bind", "Hub Network: Bind Agent"), ("network/connection/grant", "Hub Network: Connection Grant"),
  ("network/rendezvous/ticket", "Hub Network: Rendezvous Ticket"), ("network/resource/update", "Hub Network: Manage Resources"),
  ("network/resource/revoke", "Hub Network: Manage Resources"), ("network/resource/list", "Hub Network: View Resources"),
  ("network/resource/generations", "Hub Network: View Status"), ("network/providers/list", "Hub Network: View Resources"),
  ("network/agents/list", "Hub Network: View Agents"), ("network/status/agents", "Hub Network: View Status"),
  ("network/status/connections", "Hub Network: View Status"), ("network/diagnostics", "Hub Network: View Status"),
  ("hub/net/local-agent", "Hub Network: View Local Agent"), ("hub/net/local-agent/rebind", "Hub Network: Rebind Local Agent"),
  ("hub/net/node/set", "Hub Network: Configure Node"), ("network/gateway/advertise", "Hub Network: Provide Gateway"),
  ("network/gateway/remove", "Hub Network: Provide Gateway"), ("network/gateway/list", "Hub Network: Use Gateway"),
  ("network/gateway/grant", "Hub Network: Use Gateway"), ("network/gateway/revocations", "Hub Network: Use Gateway"),
  ("network/gateway/diagnostics", "Hub Network: View Status"),
  ("hub/net/apple-agent/bind", "Hub Network: Bind Apple Local Agent"), ("hub/net/apple-agent/renew", "Hub Network: Renew Apple Local Agent"),
  ("hub/net/apple-agent/unbind", "Hub Network: Unbind Apple Local Agent"),
]

/// `hub-net-node.json`: the node agents use. There is no built-in node: `null` until an owner sets one.
final class NetNodeStore {
  private(set) var value: String?
  let store: JSONStore
  init(storage: Storage) {
    store = storage.store("hub-net-node.json")
    store.encode = { [unowned self] in value.map { .string($0) } ?? .null }
  }
  func load() {
    store.load { json in value = Self.validate(json) }
  }
  func set(_ input: JSON?) throws {
    if let input, !input.isNull {
      guard let node = Self.validate(input) else { throw ChannelFailure("invalid node address") }
      value = node
    } else {
      value = nil
    }
    store.writeNow()
  }
  private static func validate(_ json: JSON) -> String? {
    guard let text = json.string, !text.isEmpty, text == text.trimmingCharacters(in: .whitespacesAndNewlines) else { return nil }
    return text
  }
}

extension Hub {
  /// A coded network error reaches the gateway routes' callers as `code: message`, as in hub-server
  private func gatewayError(_ body: () throws -> JSON) throws -> JSON {
    do {
      return try body()
    } catch let failure as ChannelFailure {
      if let code = failure.code?.string, !failure.message.hasPrefix(code) { throw ChannelFailure("\(code): \(failure.message)") }
      throw failure
    }
  }

  func registerNetworkRoutes() {
    let network = self.network
    router
      .post("network/shares/replace") { [unowned self] call in
        ["shares": .array(try network.replaceShares(call.body?["shares"]?.array ?? [], connection: connection(call.peer)))]
      }
      .stream("network/shares/published") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .network) { .array(network.publishedProviders(connection)) }
      }
      .post("hub/net/bind", answering: { [unowned self] call in
        network.bind(call.body, connection: connection(call.peer), path: call.path) { call.finish($0.map { $0 }) }
      })
      .stream("hub/net/local-agent") { [unowned self] call in
        try live.stream(call, topic: .network) { network.localAgent.status() }
      }
      .post("hub/net/local-agent/rebind") { call in
        try network.localAgent.authorizeRebind(call.body?["key"]?.string)
        network.onStateChanged()
        return ["success": true]
      }
      .post("hub/net/apple-agent/bind") { [unowned self] call in
        let status = try network.appleAgent(call.body, connection: connection(call.peer), renew: false)
        return ["success": true, "status": status, "hubKey": .string(hubKey)]
      }
      .post("hub/net/apple-agent/renew") { [unowned self] call in
        ["success": true, "status": try network.appleAgent(call.body, connection: connection(call.peer), renew: true)]
      }
      .post("hub/net/apple-agent/unbind") { [unowned self] call in
        ["success": true, "status": try network.unbindAppleAgent(call.body, connection: connection(call.peer))]
      }
      .post("network/connection/grant") { [unowned self] call in
        ["grant": try network.connectionGrant(call.body, connection: connection(call.peer))]
      }
      .post("network/rendezvous/ticket") { [unowned self] call in
        ["ticket": try network.rendezvousTicket(call.body, connection: connection(call.peer))]
      }
      .post("network/gateway/advertise") { [unowned self] call in
        try gatewayError { ["status": try network.advertiseGateway(call.body, connection: connection(call.peer))] }
      }
      .post("network/gateway/remove") { [unowned self] call in
        try gatewayError { ["revocation": try network.removeGateway(call.body, connection: connection(call.peer))] }
      }
      .post("network/gateway/grant") { [unowned self] call in
        ["grant": try network.issueGatewayGrant(call.body, connection: connection(call.peer))]
      }
      .stream("network/gateway/list") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .network) { .array(network.listGateways(connection)) }
      }
      .stream("network/gateway/revocations") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .network) { .array(network.listGatewayRevocations(connection)) }
      }
      .stream("network/gateway/diagnostics") { [unowned self] call in
        try live.stream(call, topic: .network) { [] }
      }
      .post("network/resource/update") { [unowned self] call in
        try network.updateResourcePolicy(call.body, connection: connection(call.peer))
        return ["success": true]
      }
      .post("network/resource/revoke") { [unowned self] call in
        ["generation": .int(try network.revokeResource(call.body, connection: connection(call.peer)))]
      }
      .stream("network/resource/list") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .network) { .array(network.listResources(connection)) }
      }
      .stream("network/resource/generations") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .networkGenerations) { .array(network.currentGenerations(connection)) }
      }
      .stream("network/providers/list") { [unowned self] call in
        let connection = connection(call.peer)
        let body = call.body
        try live.stream(call, topic: .network) { .array(try network.listProviders(body, connection: connection)) }
      }
      .stream("network/agents/list") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .network) { .array(network.listAgents(connection)) }
      }
      .stream("network/status/agents") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .network) { .array(network.agentStatus(connection)) }
      }
      // Agents don't report connection states to hub-server either, so these stay empty
      .stream("network/status/connections") { [unowned self] call in try live.stream(call, topic: .network) { [] } }
      .stream("network/diagnostics") { [unowned self] call in try live.stream(call, topic: .network) { [] } }
      .stream("network/devices/revoked") { [unowned self] call in
        let connection = connection(call.peer)
        try live.stream(call, topic: .networkRevoked) { .array(network.revokedDevices(connection)) }
      }
      // Cross-machine test completions of the HUBTESTENV harness, in memory, owners only
      .post("hub/net/test/complete") { [unowned self] call in
        guard let key = connection(call.peer).key else { throw ChannelFailure("unauthorized") }
        let result = call.body?.string ?? call.body.map(\.text) ?? ""
        testResults[key] = ["key": .string(key), "result": .string(result), "completedAt": .string(isoNow())]
        return ["success": true]
      }
      .stream("hub/net/test/results") { [unowned self] call in
        for result in testResults.values { call.send(result) }
        call.finish()
      }
      .stream("hub/net/list") { [unowned self] call in try live.stream(call, topic: .netList) { [unowned self] in netList } }
      .stream("hub/net/node") { [unowned self] call in try live.stream(call, topic: .netNode) { [unowned self] in JSON(netNode.value) } }
      .post("hub/net/node/set") { [unowned self] call in
        try netNode.set(call.body)
        live.changed(.netNode)
        return nil
      }
  }

  /// `hub/net/list`: agents offering invitations (`net/invite`), with the address they connect from
  var netList: JSON {
    .array(providers(of: "net/invite").compactMap { connection in
      guard let key = connection.key else { return nil }
      let ip = connection.ip == "::1" ? "127.0.0.1" : (connection.ip ?? "")
      return ["id": .string(key), "localIp": .string(ip)]
    })
  }

  func observeNetwork() {
    network.onStateChanged = { [unowned self] in
      live.changed(.network, .devices)
    }
    network.onGenerationChanged = { [unowned self] in live.changed(.networkGenerations) }
    network.onRevokedDevicesChanged = { [unowned self] in live.changed(.networkRevoked) }
    network.onBindApprove = { [unowned self] connection in
      if let id = connection.certificate?.deviceId { _ = try? approve(id) }
    }
    network.deviceLabel = { [unowned self] id in registry.device(id)?.name }
  }
}
