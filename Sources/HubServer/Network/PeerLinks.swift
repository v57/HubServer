import ChannelServer
import Foundation

/// Peer link grants (hub-net-node's PROTOCOL.md, "Peer links"): the hub signs, for each member, a `hub` link to the
/// hub's machine. With it the member reaches the hub over a direct WireGuard path the coordinator introduces, also
/// from a network where it can't reach the hub itself. The machine reaches the member's own shares it may open through
/// the same link. A member also gets a `share` link to each other member whose device fronts a share it may open (an
/// iPad watching an iPhone's camera), opening those ports there and nothing back. Devices check a grant against the hub
/// key they pinned and decide on their own; the coordinator only forwards it.
extension NetworkAPI {
  /// A grant lasts a month; the hub issues it again once half of that has passed
  static let peerLinkLifetime: TimeInterval = 30 * 24 * 3600
  /// `share` links a member gets at most: a device has 16 links (hub-net-node's PROTOCOL.md), one of them its hub link
  static let maxShareLinks = 15

  /// `network/links`: the caller's grants, the coordinator to meet the other side at, and whether the caller is the
  /// hub's machine (it accepts members' links rather than opening one)
  func links(_ connection: HubConnection, coordinator: String) throws -> JSON {
    let caller = try authenticatedProfile(connection)
    let host = hubHostProfile
    var grants: [JSON] = []
    if let host, host.key != caller.key {
      grants.append(peerLinkGrant(purpose: "hub", a: caller, b: host, ports: hostSharePorts(host, connection),
        back: memberSharePorts(caller, host: host)))
      for (provider, ports) in otherMemberSharePorts(caller, host: host, connection) {
        grants.append(peerLinkGrant(purpose: "share", a: caller, b: provider, ports: ports, back: []))
      }
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

  /// The ports of the shares the member's device fronts that the hub's machine may open: a camera on a phone, watched
  /// from the hub's Mac. Other members don't reach them, as they have no link to the member
  private func memberSharePorts(_ member: AgentProfile, host: AgentProfile) -> [(protocol: String, port: Int)] {
    var ports: [String: (protocol: String, port: Int)] = [:]
    let machine = Principal(key: host.key, device: host.device)
    for provider in agents.listProviders where provider.key == member.key {
      guard let resource = registry.resource(provider.resourceId), canAccessShare(resource, machine) else { continue }
      ports["\(provider.protocol)/\(provider.port)"] = (provider.protocol, provider.port)
    }
    return ports.values.sorted { $0.port != $1.port ? $0.port < $1.port : $0.protocol < $1.protocol }
  }

  /// The other members whose devices front shares the caller may open, with those ports, for at most `maxShareLinks`
  /// of them (a device has 16 links, one of them its hub link). The hub's machine isn't one of them: the hub link
  /// reaches it, and it reaches the members' shares through their hub links
  private func otherMemberSharePorts(
    _ caller: AgentProfile, host: AgentProfile, _ connection: HubConnection
  ) -> [(AgentProfile, [(protocol: String, port: Int)])] {
    var byProvider: [String: [String: (protocol: String, port: Int)]] = [:]
    for provider in agents.listProviders where provider.key != caller.key && provider.key != host.key {
      guard let resource = registry.resource(provider.resourceId), canAccessShare(resource, connection) else { continue }
      byProvider[provider.key, default: [:]]["\(provider.protocol)/\(provider.port)"] = (provider.protocol, provider.port)
    }
    var links: [(AgentProfile, [(protocol: String, port: Int)])] = []
    for key in byProvider.keys.sorted() where links.count < Self.maxShareLinks {
      guard let profile = agents.profile(key), profile.wireGuardKey != caller.wireGuardKey,
        !profile.overlayAddresses.isEmpty, let ports = byProvider[key]
      else { continue }
      links.append((profile, ports.values.sorted { $0.port != $1.port ? $0.port < $1.port : $0.protocol < $1.protocol }))
    }
    return links
  }

  /// A signed grant between `a` and `b`: a `hub` grant joins a member (`a`) and the hub's machine (`b`), a `share` grant
  /// a member (`a`) and another member fronting shares it may open (`b`). `a` routes `b`'s overlay addresses through
  /// `b` and may open `ports` there, `b` routes `a`'s addresses back and may open `back` on `a`
  private func peerLinkGrant(
    purpose: String, a: AgentProfile, b: AgentProfile, ports: [(protocol: String, port: Int)],
    back: [(protocol: String, port: Int)]
  ) -> JSON {
    let sides = [purpose, a.key, a.wireGuardKey, b.key, b.wireGuardKey]
      + a.overlayAddresses + b.overlayAddresses + ports.map { "\($0.protocol)/\($0.port)" }
      + back.map { "<\($0.protocol)/\($0.port)" }
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
      "hubNetworkId": .string(hubNetworkId), "purpose": .string(purpose), "a": side(a), "b": side(b),
      "aViaB": JSON(b.overlayAddresses.map(Self.hostRoute)), "bViaA": JSON(a.overlayAddresses.map(Self.hostRoute)),
      "aToB": .array(ports.map { ["protocol": .string($0.protocol), "port": .int($0.port)] }), "bToA": .array(back.map { ["protocol": .string($0.protocol), "port": .int($0.port)] }),
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
