import ChannelServer
import Foundation

/// Peer link grants (hub-net-node's PROTOCOL.md, "Peer links"): the hub signs, for each member, a `hub` link to the
/// hub's machine. With it the member reaches the hub over a direct WireGuard path the coordinator introduces, also
/// from a network where it can't reach the hub itself. Devices check a grant against the hub key they pinned and decide
/// on their own; the coordinator only forwards it.
extension NetworkAPI {
  /// A grant lasts a month; the hub issues it again once half of that has passed
  static let peerLinkLifetime: TimeInterval = 30 * 24 * 3600

  /// `network/links`: the caller's grants, the coordinator to meet the other side at, and whether the caller is the
  /// hub's machine (it accepts members' links rather than opening one)
  func links(_ connection: HubConnection, coordinator: String) throws -> JSON {
    let caller = try authenticatedProfile(connection)
    let host = hubHostProfile
    var grants: [JSON] = []
    if let host, host.key != caller.key {
      grants.append(peerLinkGrant(purpose: "hub", member: caller, host: host, ports: hostSharePorts(host, connection)))
    }
    return [
      "version": .int(NetworkFoundation.wireVersion), "hubKey": .string(hubKey), "hubNetworkId": .string(hubNetworkId),
      "coordinator": .string(coordinator), "hubHost": .bool(host?.key == caller.key), "grants": .array(grants),
    ]
  }

  /// The profile of the agent bound as the hub's own (the machine agent, or the Hub app on that machine), while it's
  /// registered
  var hubHostProfile: AgentProfile? {
    guard let key = localAgent.status()["key"]?.string else { return nil }
    return agents.profile(key)
  }

  /// The ports of the shares the hub's machine fronts that the caller may open, besides the hub's: a service's web UI
  /// on that machine is reached through the same link. Its SSH server too, for callers that may sign in there
  private func hostSharePorts(_ host: AgentProfile, _ connection: HubConnection) -> [(protocol: String, port: Int)] {
    var ports: [String: (protocol: String, port: Int)] = ["tcp/\(hubPort)": ("tcp", hubPort)]
    for provider in agents.listProviders where provider.key == host.key {
      guard let resource = registry.resource(provider.resourceId), canAccessShare(resource, connection) else { continue }
      ports["\(provider.protocol)/\(provider.port)"] = (provider.protocol, provider.port)
    }
    if let device = host.device, let port = deviceSSHPort(device), canUseHostSSH(connection) {
      ports["tcp/\(port)"] = ("tcp", port)
    }
    return ports.values.sorted { $0.port != $1.port ? $0.port < $1.port : $0.protocol < $1.protocol }
  }

  /// The signed `hub` grant between a member and the hub's machine: the member routes the machine's overlay addresses
  /// through it and may open `ports` there (the hub's and its shares'), the machine routes the member's addresses back
  private func peerLinkGrant(purpose: String, member: AgentProfile, host: AgentProfile, ports: [(protocol: String, port: Int)]) -> JSON {
    let sides = [purpose, member.key, member.wireGuardKey, host.key, host.wireGuardKey]
      + member.overlayAddresses + host.overlayAddresses + ports.map { "\($0.protocol)/\($0.port)" }
    let cacheKey = sides.joined(separator: "\u{0}")
    if let cached = peerLinkGrants[cacheKey], cached.expiresAt.timeIntervalSinceNow > Self.peerLinkLifetime / 2 {
      return cached.grant
    }
    let now = Date()
    let expiresAt = now.addingTimeInterval(Self.peerLinkLifetime)
    func side(_ profile: AgentProfile) -> JSON {
      ["key": .string(profile.key), "wireGuardKey": .string(profile.wireGuardKey), "member": .string(profile.member ?? profile.key),
       "addresses": JSON(profile.overlayAddresses)]
    }
    let grant = signed(.peerLink, [
      "version": .int(NetworkFoundation.wireVersion), "grantId": .string(newId()), "hubKey": .string(hubKey),
      "hubNetworkId": .string(hubNetworkId), "purpose": .string(purpose), "a": side(member), "b": side(host),
      "aViaB": JSON(host.overlayAddresses.map(Self.hostRoute)), "bViaA": JSON(member.overlayAddresses.map(Self.hostRoute)),
      "aToB": .array(ports.map { ["protocol": .string($0.protocol), "port": .int($0.port)] }), "bToA": [],
      "issuedAt": .string(isoDate(now)), "expiresAt": .string(isoDate(expiresAt)), "signature": "",
    ])
    peerLinkGrants[cacheKey] = (grant, expiresAt)
    return grant
  }

  /// `100.96.0.2` → `100.96.0.2/32`, an IPv6 address → `/128`
  static func hostRoute(_ address: String) -> String {
    address.contains(":") ? "\(address)/128" : "\(address)/32"
  }

  /// A revoked device's grants are never handed out again
  func forgetPeerLinkGrants(of key: String) {
    peerLinkGrants = peerLinkGrants.filter { !$0.key.split(separator: "\u{0}").contains { $0 == key } }
  }
}
