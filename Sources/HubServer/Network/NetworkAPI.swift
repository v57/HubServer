import ChannelServer
import Foundation

/// Hub Network's control plane (hub-server's src/network/api.ts): agents bind and get overlay addresses, services
/// publish shares through their device's agent, the hub signs connection grants, rendezvous tickets and gateway
/// grants with its key, and owners manage resources, members and revocation. Confined to the hub's queue.
final class NetworkAPI {
  let registry: NetworkRegistry
  let agents = AgentRegistry()
  let localAgent: LocalAgentBindings
  private let security: Security
  private let key: HubKeyPair
  /// Where the `machine` agent's proof comes from
  var localAgentEndpoint = LocalAgent.defaultEndpoint
  private let queue: DispatchQueue

  /// Something members, agents, providers or resources show changed
  var onStateChanged: () -> Void = {}
  /// A resource generation changed: `network/resource/generations` recomputes
  var onGenerationChanged: () -> Void = {}
  var onRevokedDevicesChanged: () -> Void = {}
  /// A pending device whose agent passed its bind proof is approved (protocol.md section 10)
  var onBindApprove: (HubConnection) -> Void = { _ in }
  /// Device names for member DNS names
  var deviceLabel: (String) -> String? = { _ in nil }

  private var consumedAttestations: [String: Date] = [:]
  /// Agents that hold grants per resource, which generation changes reach
  private var grantAgents: [String: Set<String>] = [:]
  private var gateways: [String: (status: JSON, connectionId: String, generation: Int)] = [:]
  private var gatewayGenerations: [String: Int] = [:]
  private var gatewayRevocations: [String: JSON] = [:]
  private var gatewayGrantAgents: [String: Set<String>] = [:]
  /// Device of each connected agent key that bound from a device connection
  private var agentDevices: [String: String] = [:]
  private var applyingPolicy = false

  init(storage: Storage, security: Security, key: HubKeyPair, queue: DispatchQueue) {
    registry = NetworkRegistry(storage: storage)
    localAgent = LocalAgentBindings(storage: storage)
    self.security = security
    self.key = key
    self.queue = queue
    localAgent.onAppleInvalidated = { [unowned self] in onStateChanged() }
  }

  func load() {
    registry.load()
    localAgent.load()
    if !registry.corrupt { migratePolicies() }
    registry.setHubKey(key.publicKey)
  }

  private var hubNetworkId: String { registry.hubNetworkId }
  private var hubKey: String { registry.hubKey }

  private func requireKey(_ connection: HubConnection) throws -> String {
    guard let key = connection.key else { throw networkError("unauthorized", "authentication required") }
    return key
  }

  private func isOwner(_ connection: HubConnection) -> Bool { security.isOwner(connection.principal) }

  // MARK: Shares

  /// `network/shares/replace`: a service atomically replaces the shares it publishes on this connection. The whole
  /// request is validated before anything changes.
  func replaceShares(_ shares: [JSON], connection: HubConnection) throws -> [JSON] {
    let ownerKey = try requireKey(connection)
    var planned: [(resource: NetworkResource, provider: LiveProvider, publication: JSON, attestation: JSON)] = []
    var seen = Set<String>()
    for share in shares {
      try validateShare(share)
      let attestation = share["attestation"]!
      let agentKey = attestation["key"]?.string ?? ""
      guard let profile = agents.profile(agentKey) else { throw networkError("agent_unavailable", "agent is not connected") }
      let name = share["name"]!.string!
      guard verifyAttestation(attestation, share: share, serviceKey: ownerKey, profile: profile) else {
        throw networkError("invalid_attestation", "service attestation is invalid or expired")
      }
      // The share's address is the service's device: only that device's agent may front it
      if let device = connection.device, let agentDevice = agentDevices[agentKey], agentDevice != device {
        throw networkError("share_device_mismatch", "the agent runs on another device than the service")
      }
      guard let overlayAddress = profile.overlayAddresses.first else {
        throw networkError("agent_unavailable", "agent has no overlay address")
      }
      let resourceId = try NetworkFoundation.stableResourceId(ownerKey: ownerKey, shareName: name)
      guard seen.insert(resourceId).inserted else { throw networkError("invalid_request", "duplicate share name in replacement set") }
      var policy: JSON
      var generation: Int
      if let existing = registry.resource(resourceId) {
        guard existing.ownerKey == ownerKey else { throw networkError("forbidden", "resource owned by different key") }
        policy = existing.policy
        generation = existing.generation
      } else {
        policy = share["policy"] ?? ["mode": "private"]
        try validateNetworkPolicy(policy)
        generation = 0
      }
      let authority = try NetworkFoundation.canonicalAuthority(hubNetworkId: hubNetworkId, ownerKey: ownerKey, shareName: name)
      let resource = NetworkResource(resourceId: resourceId, ownerKey: ownerKey, shareName: name, authority: authority, policy: policy, generation: generation)
      let providerId = newId()
      let protocolName = share["protocol"]!.string!
      let port = share["target"]!["port"]!.int!
      let provider = LiveProvider(providerId: providerId, resourceId: resourceId, serviceKey: ownerKey, key: agentKey,
        protocol: protocolName, overlayAddress: overlayAddress, port: port, connectedAt: isoNow())
      let publication: JSON = ["version": .int(NetworkFoundation.wireVersion), "resourceId": .string(resourceId), "authority": .string(authority),
        "providerId": .string(providerId), "protocol": .string(protocolName), "overlayAddress": .string(overlayAddress), "port": .int(port)]
      planned.append((resource, provider, publication, attestation))
    }
    agents.clearConnectionProviders(connection.id)
    var publications: [JSON] = []
    for entry in planned {
      let isNew = registry.resource(entry.resource.resourceId) == nil
      try registry.registerResource(entry.resource)
      if isNew { setPolicyGrants(entry.resource, by: ownerKey) }
      agents.registerProvider(entry.provider, connectionId: connection.id)
      if let id = entry.attestation["attestationId"]?.string {
        consumedAttestations[id] = NetworkTime.parse(entry.attestation["expiresAt"]?.string) ?? Date()
      }
      publications.append(entry.publication)
    }
    onStateChanged()
    return publications
  }

  private func validateShare(_ share: JSON) throws {
    guard share["version"]?.int == NetworkFoundation.wireVersion, let protocolName = share["protocol"]?.string,
      protocolName == "tcp" || protocolName == "udp", let name = share["name"]?.string, let host = share["target"]?["host"]?.string,
      !host.isEmpty, case .int(let port) = share["target"]?["port"] ?? .null, (1...65535).contains(port), share["attestation"]?.object != nil
    else { throw networkError("invalid_request", "invalid network share") }
    do {
      _ = try NetworkFoundation.normalizeShareName(name)
      if let policy = share["policy"] { try validateNetworkPolicy(policy) }
    } catch {
      throw networkError("invalid_request", "invalid network share")
    }
  }

  private func verifyAttestation(_ attestation: JSON, share: JSON, serviceKey: String, profile: AgentProfile) -> Bool {
    guard attestation["version"]?.int == NetworkFoundation.wireVersion,
      let issuedAt = NetworkTime.parse(attestation["issuedAt"]?.string), let expiresAt = NetworkTime.parse(attestation["expiresAt"]?.string)
    else { return false }
    let now = Date()
    guard issuedAt <= now.addingTimeInterval(30), expiresAt > now, expiresAt > issuedAt, expiresAt.timeIntervalSince(issuedAt) <= 600 else { return false }
    consumedAttestations = consumedAttestations.filter { $0.value > now }
    if let id = attestation["attestationId"]?.string, consumedAttestations[id] != nil { return false }
    guard attestation["serviceKey"]?.string == serviceKey, attestation["key"]?.string == profile.key,
      attestation["shareName"]?.string == share["name"]?.string, attestation["protocol"]?.string == share["protocol"]?.string,
      attestation["target"]?["host"]?.string == share["target"]?["host"]?.string, attestation["target"]?["port"] == share["target"]?["port"]
    else { return false }
    return NetworkSignature.verify(.agentAttestation, attestation, publicKey: profile.key)
  }

  /// `network/shares/published`: providers of the caller's services, all of them for owners
  func publishedProviders(_ connection: HubConnection) -> [JSON] {
    let owner = isOwner(connection)
    return agents.listProviders.filter { $0.serviceKey == connection.key || owner }.map(\.json)
  }

  // MARK: Binding

  /// `hub/net/bind`: `machine` (proven by the hub host's agent socket), `apple-app` (owners) or `join` (an
  /// invitation admission, or an existing member)
  func bind(_ request: JSON?, connection: HubConnection, path: String, completion: @escaping (Result<JSON, Error>) -> Void) {
    let request = request ?? .null
    switch request["bindingKind"]?.string {
    case "machine":
      do {
        let key = try requireKey(connection)
        try checkProfile(request)
        let endpoint = localAgentEndpoint
        let connectionId = connection.id
        DispatchQueue.global().async { [weak self] in
          let proof = Result { try LocalAgent.prove(endpoint: endpoint, key: key, connectionId: connectionId) }
          self?.queue.async {
            guard let self else { return }
            do {
              let proof = try proof.mapError { error -> Error in
                self.localAgent.failed("\(error)")
                return networkError("local_agent_unavailable", "authenticated local hub-net proof unavailable")
              }.get()
              do {
                try self.localAgent.registerMachine(key: key, connectionId: connectionId, proof: proof)
              } catch let failure as ChannelFailure where failure.message == "local_agent_rebind_required" {
                throw networkError("local_agent_rebind_required", "owner authorization required to replace bound local agent")
              } catch let failure as ChannelFailure where failure.message == "local_agent_proof_mismatch" {
                throw networkError("local_agent_proof_mismatch", "local proof agent does not match authenticated connection")
              }
              completion(.success(try self.registerProfile(request, connection: connection)))
            } catch {
              completion(.failure(error))
            }
          }
        }
      } catch {
        completion(.failure(error))
      }
    case "apple-app":
      completion(Result {
        guard isOwner(connection) else { throw networkError("forbidden", "owner permission required for \(path)") }
        return try registerProfile(request, connection: connection)
      })
    case "join":
      completion(Result { try bindJoin(request, connection: connection) })
    default:
      completion(.failure(networkError("invalid_request", "unsupported agent binding kind")))
    }
  }

  private func checkProfile(_ request: JSON) throws {
    guard request["version"]?.int == NetworkFoundation.wireVersion else {
      throw networkError("unsupported_version", "unsupported agent profile version")
    }
    guard let wireGuardKey = request["wireGuardKey"]?.string, !wireGuardKey.isEmpty else {
      throw networkError("invalid_request", "WireGuard key is required")
    }
  }

  /// A joiner arrives through its inviter's bootstrap tunnel. A key that was never admitted presents the admission an
  /// agent bound to this network signed for it; members re-bind without one.
  private func bindJoin(_ request: JSON, connection: HubConnection) throws -> JSON {
    let key = try requireKey(connection)
    try checkProfile(request)
    let wireGuardKey = request["wireGuardKey"]!.string!
    var admitted = false
    if let admission = request["admission"], let inviterKey = admission["inviterServiceKey"]?.string,
      agents.profile(inviterKey) != nil, inviterKey != key
    {
      admitted = NetworkValidation.joinAdmission(admission, joinerKey: key, joinerWireGuardKey: wireGuardKey)
    }
    // A fresh invitation lets a member rejoin with new tunnel keys; without one the bound WireGuard key stays
    if let existing = agents.profile(key), existing.wireGuardKey != wireGuardKey, !admitted {
      throw networkError("forbidden", "profile WireGuard key is already bound")
    }
    if !isMember(connection), !admitted {
      throw networkError("forbidden", "a valid invitation admission is required to join")
    }
    return try registerProfile(request, connection: connection)
  }

  private func registerProfile(_ request: JSON, connection: HubConnection) throws -> JSON {
    let key = try requireKey(connection)
    try checkProfile(request)
    // One agent per device. Its proof passed, so a pending device is approved and the member is the device.
    if let deviceId = connection.certificate?.deviceId {
      // Another key takes over only while the old agent is offline (a reinstall), keeping the addresses
      if agentDevices.contains(where: { $0.value == deviceId && $0.key != key }) {
        throw networkError("device_endpoint_exists", "this device already has a network endpoint")
      }
      if connection.device == nil { onBindApprove(connection) }
    }
    let memberKey = connection.device.map(deviceMember) ?? key
    if let device = connection.device {
      registry.moveMember(from: key, to: memberKey)
      agentDevices[key] = device
      if registry.clearRevokedDevice(device) { onRevokedDevicesChanged() }
    }
    let addresses = try registry.allocateAddresses(memberKey)
    let profile = AgentProfile(wireGuardKey: request["wireGuardKey"]!.string!, name: request["name"]?.string,
      platform: request["platform"]?.string, key: key, member: memberKey, device: connection.device,
      overlayAddresses: [addresses.ipv4, addresses.ipv6], connectedAt: isoNow())
    agents.registerProfile(profile, connectionId: connection.id)
    registry.rememberMember(memberKey, StoredMember(key: memberKey != key ? key : nil, device: memberKey != key ? connection.device : nil,
      wireGuardKey: profile.wireGuardKey, name: profile.name, platform: profile.platform, lastSeen: profile.connectedAt))
    onStateChanged()
    return ["success": true, "profile": profile.json, "hubKey": .string(hubKey), "hubNetworkId": .string(hubNetworkId)]
  }

  /// A member by its device or, for legacy agents, by its key
  private func isMember(_ connection: HubConnection) -> Bool {
    if let key = connection.key, registry.hasAllocation(key) { return true }
    guard let device = connection.device ?? connection.certificate?.deviceId else { return false }
    return registry.hasAllocation(deviceMember(device))
  }

  private func authenticatedProfile(_ connection: HubConnection) throws -> AgentProfile {
    let key = try requireKey(connection)
    guard let profile = agents.profile(key) else { throw networkError("unauthorized", "agent profile not registered") }
    return profile
  }

  // MARK: Apple app agent

  func appleAgent(_ request: JSON?, connection: HubConnection, renew: Bool) throws -> JSON {
    guard request?["version"]?.int == NetworkFoundation.wireVersion else {
      throw networkError("unsupported_version", "unsupported Apple app-agent version")
    }
    let assertion = request?["assertion"] ?? .null
    let profile = try authenticatedProfile(connection)
    guard assertion["wireGuardKey"]?.string == profile.wireGuardKey, assertion["hubNetworkId"]?.string == hubNetworkId else {
      throw networkError("forbidden", "Apple readiness does not match registered profile, WireGuard key, or Hub")
    }
    guard NetworkValidation.appleReadiness(assertion, key: profile.key, hubNetworkId: hubNetworkId) else {
      throw networkError("forbidden", "invalid or expired Apple app-agent readiness assertion")
    }
    do {
      if renew {
        try localAgent.renewApple(assertion, connectionId: connection.id, key: profile.key)
      } else {
        try localAgent.bindApple(assertion, connectionId: connection.id, key: profile.key)
      }
    } catch {
      throw networkError("forbidden", ChannelFailure(error).message)
    }
    scheduleAppleExpiry()
    onStateChanged()
    return localAgent.status()
  }

  func unbindAppleAgent(_ request: JSON?, connection: HubConnection) throws -> JSON {
    guard request?["version"]?.int == NetworkFoundation.wireVersion else {
      throw networkError("unsupported_version", "unsupported Apple app-agent version")
    }
    _ = try authenticatedProfile(connection)
    guard request?["hubNetworkId"]?.string == hubNetworkId else {
      throw networkError("forbidden", "Apple app-agent binding does not match registered profile or Hub")
    }
    do {
      try localAgent.unbindApple(request ?? .null, connectionId: connection.id)
    } catch {
      throw networkError("forbidden", "Apple app-agent binding is not owned by this connection")
    }
    onStateChanged()
    return localAgent.status()
  }

  private func scheduleAppleExpiry() {
    guard let apple = localAgent.apple, let expires = NetworkTime.parse(apple.expiresAt) else { return }
    queue.asyncAfter(deadline: .now() + max(0, expires.timeIntervalSinceNow) + 0.05) { [weak self] in
      self?.localAgent.expireApple()
    }
  }

  // MARK: Grants and tickets

  /// `network/connection/grant`: a hub-signed grant for the caller to reach a share's provider
  func connectionGrant(_ body: JSON?, connection: HubConnection) throws -> JSON {
    let callerKey = try requireKey(connection)
    guard let resourceId = body?["resourceId"]?.string, let resource = registry.resource(resourceId) else {
      throw networkError("resource_unavailable", "resource does not exist")
    }
    guard let caller = agents.profile(callerKey) else { throw networkError("unauthorized", "caller profile not registered") }
    let callerWireGuardKey = body?["callerWireGuardKey"]?.string ?? ""
    guard caller.wireGuardKey == callerWireGuardKey else {
      throw networkError("forbidden", "caller WireGuard key does not match the registered profile")
    }
    guard canAccessShare(resource, connection) else { throw networkError("forbidden", "not authorized for this resource") }
    guard let provider = agents.selectProvider(resourceId, preferred: body?["preferredProviderId"]?.string) else {
      throw networkError("provider_unavailable", "no live provider for resource")
    }
    guard let target = agents.profile(provider.key) else { throw networkError("provider_unavailable", "agent not connected") }
    let destinationIsIPv6 = provider.overlayAddress.contains(":")
    guard let callerAddress = caller.overlayAddresses.first(where: { $0.contains(":") == destinationIsIPv6 }) else {
      throw networkError("provider_unavailable", "caller has no compatible overlay address")
    }
    let now = Date()
    var grant: JSON = [
      "version": .int(NetworkFoundation.wireVersion), "grantId": .string(newId()), "hubKey": .string(hubKey),
      "hubNetworkId": .string(hubNetworkId), "callerKey": .string(callerKey), "callerWireGuardKey": .string(callerWireGuardKey),
      "callerAddress": .string(callerAddress), "targetKey": .string(target.key), "targetWireGuardKey": .string(target.wireGuardKey),
      "resourceId": .string(resourceId), "providerId": .string(provider.providerId), "protocol": .string(provider.protocol),
      "destinationAddress": .string(provider.overlayAddress), "destinationPort": .int(provider.port),
      "generation": .int(resource.generation), "issuedAt": .string(isoDate(now)),
      "expiresAt": .string(isoDate(now.addingTimeInterval(NetworkTime.connectionGrantLifetime))), "signature": "",
    ]
    grant = signed(.connectionGrant, grant)
    grantAgents[resourceId, default: []].formUnion([caller.key, target.key])
    return grant
  }

  private func signed(_ purpose: SignaturePurpose, _ envelope: JSON) -> JSON {
    var object = envelope.object ?? [:]
    object["signature"] = .string(NetworkSignature.sign(purpose, envelope, key: key))
    return .object(object)
  }

  /// `network/rendezvous/ticket`: lets a bound agent use the network's node
  func rendezvousTicket(_ body: JSON?, connection: HubConnection) throws -> JSON {
    let key = try requireKey(connection)
    guard agents.profile(key) != nil else { throw networkError("unauthorized", "agent profile not registered") }
    let roles = body?["roles"]?.array ?? ["rendezvous"]
    guard roles == ["rendezvous"] else { throw networkError("invalid_request", "only the rendezvous node role is supported") }
    let now = Date()
    let ticket: JSON = [
      "version": .int(NetworkFoundation.wireVersion), "ticketId": .string(newId()), "hubKey": .string(hubKey),
      "hubNetworkId": .string(hubNetworkId), "key": .string(key), "nodeId": body?["nodeId"] ?? .null, "roles": ["rendezvous"],
      "sessionPurpose": "peer-connect", "issuedAt": .string(isoDate(now)),
      "expiresAt": .string(isoDate(now.addingTimeInterval(NetworkTime.rendezvousTicketLifetime))), "signature": "",
    ]
    return signed(.rendezvousTicket, ticket)
  }

  // MARK: Gateways

  private static let endpointPattern = try! NSRegularExpression(pattern: #"^(?:[^:\[\]\s]+:\d{1,5}|\[[0-9a-fA-F:]+\]:\d{1,5})$"#)

  func advertiseGateway(_ body: JSON?, connection: HubConnection) throws -> JSON {
    let profile = try authenticatedProfile(connection)
    let capability = body?["capability"] ?? .null
    let endpoint = body?["endpoint"]?.string ?? ""
    let port = Int(endpoint.split(separator: ":").last ?? "") ?? 0
    guard capability["version"]?.int == NetworkFoundation.wireVersion, capability["capability"] == "internet-gateway-v1",
      let ipv4 = capability["ipv4"]?.bool, let ipv6 = capability["ipv6"]?.bool, capability["dns"]?.bool != nil,
      capability["metered"]?.bool != nil, ipv4 || ipv6, NetworkTime.parse(capability["updatedAt"]?.string) != nil,
      NetworkAPI.endpointPattern.firstMatch(in: endpoint, range: NSRange(endpoint.startIndex..., in: endpoint)) != nil,
      (1...65535).contains(port)
    else { throw ChannelFailure("invalid_request: invalid gateway capability") }
    let generation = gatewayGenerations[profile.key] ?? 0
    let status: JSON = ["version": .int(NetworkFoundation.wireVersion), "hubNetworkId": .string(hubNetworkId), "key": .string(profile.key),
      "wireGuardKey": .string(profile.wireGuardKey), "endpoint": .string(endpoint), "capability": capability, "state": "available",
      "updatedAt": .string(isoNow())]
    gateways[profile.key] = (status, connection.id, generation)
    gatewayRevocations[profile.key] = nil
    onStateChanged()
    return status
  }

  func removeGateway(_ body: JSON?, connection: HubConnection) throws -> JSON {
    let profile = try authenticatedProfile(connection)
    guard let current = gateways[profile.key], current.connectionId == connection.id else {
      throw ChannelFailure("gateway_unavailable: gateway is not advertised by this connection")
    }
    return revokeGateway(profile.key, reason: body?["reason"]?.string ?? "provider_disabled")
  }

  private func canUseGatewayAPI(_ connection: HubConnection) -> Bool {
    guard let key = connection.key else { return false }
    return isOwner(connection) || agents.profile(key) != nil
  }

  func listGateways(_ connection: HubConnection) -> [JSON] {
    guard canUseGatewayAPI(connection) else { return [] }
    return gateways.sorted { $0.key < $1.key }.map(\.value.status)
  }

  func listGatewayRevocations(_ connection: HubConnection) -> [JSON] {
    guard let key = connection.key else { return [] }
    let owner = isOwner(connection)
    let profile = agents.profile(key)
    guard profile != nil || owner else { return [] }
    return gatewayRevocations.sorted { $0.key < $1.key }.compactMap { gatewayKey, revocation in
      owner || gatewayKey == profile?.key || gatewayGrantAgents[gatewayKey]?.contains(key) == true ? revocation : nil
    }
  }

  func issueGatewayGrant(_ body: JSON?, connection: HubConnection) throws -> JSON {
    let client = try authenticatedProfile(connection)
    guard client.key == body?["clientKey"]?.string, client.wireGuardKey == body?["clientWireGuardKey"]?.string else {
      throw networkError("gateway_not_authorized", "client binding does not match authenticated profile")
    }
    let gatewayKey = body?["gatewayKey"]?.string ?? ""
    guard let advertised = gateways[gatewayKey], advertised.status["state"] == "available" else {
      throw networkError("gateway_unavailable", "gateway is unavailable")
    }
    guard let ipv4 = body?["ipv4"]?.bool, let ipv6 = body?["ipv6"]?.bool, let dns = body?["dns"]?.bool, ipv4 || ipv6,
      !ipv4 || advertised.status["capability"]?["ipv4"] == true, !ipv6 || advertised.status["capability"]?["ipv6"] == true,
      !dns || advertised.status["capability"]?["dns"] == true
    else { throw networkError("gateway_not_authorized", "requested gateway capability is unavailable") }
    let now = Date()
    let grant: JSON = [
      "version": .int(NetworkFoundation.wireVersion), "grantId": .string(newId()), "hubKey": .string(hubKey),
      "hubNetworkId": .string(hubNetworkId), "clientKey": .string(client.key), "clientWireGuardKey": .string(client.wireGuardKey),
      "gatewayKey": .string(gatewayKey), "gatewayWireGuardKey": advertised.status["wireGuardKey"] ?? "", "ipv4": .bool(ipv4),
      "ipv6": .bool(ipv6), "dns": .bool(dns), "generation": .int(advertised.generation), "issuedAt": .string(isoDate(now)),
      "expiresAt": .string(isoDate(now.addingTimeInterval(NetworkTime.gatewayGrantLifetime))), "signature": "",
    ]
    gatewayGrantAgents[gatewayKey, default: []].formUnion([client.key, advertised.status["key"]?.string ?? gatewayKey])
    return signed(.gatewayGrant, grant)
  }

  private func revokeGateway(_ key: String, reason: String) -> JSON {
    let current = gateways.removeValue(forKey: key)
    let generation = (gatewayGenerations[key] ?? current?.generation ?? 0) + 1
    gatewayGenerations[key] = generation
    let revocation: JSON = ["version": .int(NetworkFoundation.wireVersion), "hubNetworkId": .string(hubNetworkId),
      "gatewayKey": .string(key), "generation": .int(generation), "revokedAt": .string(isoNow()), "reason": .string(reason)]
    gatewayRevocations[key] = revocation
    onStateChanged()
    return revocation
  }

  // MARK: Resources

  /// `network/resource/update`: a policy change bumps the generation, so grants of the old policy end
  func updateResourcePolicy(_ body: JSON?, connection: HubConnection) throws {
    let key = try requireKey(connection)
    guard let resourceId = body?["resourceId"]?.string, let resource = registry.resource(resourceId) else {
      throw networkError("resource_unavailable", "resource does not exist")
    }
    guard resource.ownerKey == key || isOwner(connection) else {
      throw networkError("forbidden", "only resource owner can change policy")
    }
    let policy = body?["policy"] ?? .null
    try validateNetworkPolicy(policy)
    let unchanged = NetworkSignature.canonicalJSON(resource.policy) == NetworkSignature.canonicalJSON(policy)
    try registry.updateResource(resourceId, policy: policy, generation: unchanged ? resource.generation : resource.generation + 1)
    if !unchanged, let updated = registry.resource(resourceId) {
      setPolicyGrants(updated, by: key)
      propagateGeneration(resourceId)
    }
    onStateChanged()
  }

  func revokeResource(_ body: JSON?, connection: HubConnection) throws -> Int {
    let key = try requireKey(connection)
    guard let resourceId = body?["resourceId"]?.string, let resource = registry.resource(resourceId) else {
      throw networkError("resource_unavailable", "resource does not exist")
    }
    guard resource.ownerKey == key || isOwner(connection) else { throw networkError("forbidden", "only resource owner can revoke") }
    let generation = try registry.incrementGeneration(resourceId)
    propagateGeneration(resourceId)
    onStateChanged()
    return generation
  }

  /// Stages the resource's current generation for its providers' agents and the agents holding its grants
  private func propagateGeneration(_ resourceId: String) {
    guard let resource = registry.resource(resourceId) else { return }
    let snapshot: JSON = ["version": .int(NetworkFoundation.wireVersion), "resourceId": .string(resourceId),
      "generation": .int(resource.generation), "policy": resource.policy, "updatedAt": .string(isoNow())]
    var affected = grantAgents[resourceId] ?? []
    for provider in agents.providers(of: resourceId) { affected.insert(provider.key) }
    for key in affected { agents.stageGeneration(key, snapshot) }
    onGenerationChanged()
  }

  func listResources(_ connection: HubConnection) -> [JSON] {
    registry.allResources.filter { canViewResource($0, connection) }.map(\.json)
  }

  func listProviders(_ body: JSON?, connection: HubConnection) throws -> [JSON] {
    guard let resourceId = body?["resourceId"]?.string, let resource = registry.resource(resourceId) else {
      throw networkError("resource_unavailable", "resource does not exist")
    }
    guard canViewResource(resource, connection) else { throw networkError("forbidden", "not authorized to view providers") }
    return agents.providers(of: resourceId).map(\.json)
  }

  private func visibleProviders(_ connection: HubConnection) -> [LiveProvider] {
    let visible = Set(registry.allResources.filter { canViewResource($0, connection) }.map(\.resourceId))
    return agents.listProviders.filter { visible.contains($0.resourceId) }
  }

  func currentGenerations(_ connection: HubConnection) -> [JSON] {
    guard let key = connection.key, agents.profile(key) != nil else { return [] }
    return agents.staged(key)
  }

  private func canViewResource(_ resource: NetworkResource, _ connection: HubConnection) -> Bool {
    guard let key = connection.key else { return false }
    if resource.ownerKey == key || isOwner(connection) { return true }
    guard agents.profile(key) != nil else { return false }
    return canAccessShare(resource, connection)
  }

  /// Share access is a grant (protocol.md section 9): owners and the share's own service always, unless the share
  /// is disabled; anyone else needs a `{ share }` grant
  private func canAccessShare(_ resource: NetworkResource, _ connection: HubConnection) -> Bool {
    guard resource.mode != "disabled", let key = connection.key else { return false }
    if isOwner(connection) || resource.ownerKey == key { return true }
    return security.grants.allowsShare(security.caller(connection.principal), resource.resourceId)
  }

  /// Grants a share policy stands for: hub → everyone, group → the group, keys → each key, private → none
  private func setPolicyGrants(_ resource: NetworkResource, by: String) {
    applyingPolicy = true
    defer { applyingPolicy = false }
    let object = GrantObject.share(resource.resourceId)
    security.grants.removeAll { $0.object == object }
    switch resource.mode {
    case "hub": security.grants.add(.everyone, object, by: by)
    case "group": if let group = resource.policy["group"]?.string { security.grants.add(.group(group), object, by: by) }
    case "keys": for key in resource.policy["keys"]?.strings ?? [] { security.grants.add(.key(key), object, by: by) }
    default: break
    }
  }

  /// Share grants added or removed outside a policy update end flows of the old generation
  func grantsChanged(_ changed: [Grant]) {
    guard !applyingPolicy else { return }
    var shares = Set<String>()
    for grant in changed { if case .share(let id) = grant.object { shares.insert(id) } }
    for id in shares where registry.resource(id) != nil {
      _ = try? registry.incrementGeneration(id)
      propagateGeneration(id)
    }
    if !shares.isEmpty { onStateChanged() }
  }

  /// Grants that depended on a changed group end
  func groupMembershipChanged(_ group: String) {
    var shares = Set<String>()
    for grant in security.grants.grants where grant.subject == .group(group) {
      if case .share(let id) = grant.object { shares.insert(id) }
    }
    for resource in registry.allResources {
      let byPolicy = resource.mode == "group" && resource.policy["group"]?.string == group
      guard byPolicy || shares.contains(resource.resourceId) else { continue }
      _ = try? registry.incrementGeneration(resource.resourceId)
      propagateGeneration(resource.resourceId)
    }
    onStateChanged()
  }

  func groupRenamed(_ group: String, to name: String) {
    for resource in registry.allResources where resource.mode == "group" && resource.policy["group"]?.string == group {
      try? registry.updateResource(resource.resourceId, policy: ["mode": "group", "group": .string(name)], generation: resource.generation + 1)
      propagateGeneration(resource.resourceId)
    }
    onStateChanged()
  }

  /// Turns stored share policies into grants once
  private func migratePolicies() {
    let grants = security.grants
    guard !grants.store.corrupt, !grants.migrated.contains("network") else { return }
    for resource in registry.allResources { setPolicyGrants(resource, by: "migration") }
    grants.migrated.append("network")
    grants.store.save()
  }

  // MARK: Members and devices

  /// Every member: connected profiles plus known members that are offline, so the hub host's agent keeps their
  /// peers across restarts
  func listMembers() -> [JSON] {
    let connected = agents.listProfiles
    let keys = Set(connected.map(\.key))
    let online: [JSON] = connected.map { profile in
      var object = profile.json.object!
      object["online"] = true
      if let device = agentDevices[profile.key] { object["deviceAuthority"] = .string(deviceAuthority(device, fallback: profile.name)) }
      return .object(object)
    }
    let offline: [JSON] = registry.listMembers().filter { !keys.contains($0.member.key ?? $0.key) }.map { entry in
      var object: JSONObject = ["version": .int(NetworkFoundation.wireVersion), "key": .string(entry.member.key ?? entry.key),
        "member": .string(entry.key)]
      if let device = entry.member.device { object["device"] = .string(device) }
      object["wireGuardKey"] = .string(entry.member.wireGuardKey)
      if let name = entry.member.name { object["name"] = .string(name) }
      if let platform = entry.member.platform { object["platform"] = .string(platform) }
      object["overlayAddresses"] = JSON(entry.addresses)
      object["connectedAt"] = .string(entry.member.lastSeen)
      object["online"] = false
      if let device = entry.member.device { object["deviceAuthority"] = .string(deviceAuthority(device, fallback: entry.member.name)) }
      return .object(object)
    }
    return online + offline
  }

  func deviceAuthority(_ device: String, fallback: String?) -> String {
    NetworkFoundation.deviceAuthority(hubNetworkId: hubNetworkId, deviceId: device, deviceName: deviceLabel(device) ?? fallback ?? "device")
  }

  /// `Device.overlay`: the device member's IPv4 overlay address and DNS name
  func deviceOverlay(_ device: String) -> JSON? {
    guard let addresses = registry.allocations[deviceMember(device)] else { return nil }
    return ["address": .string(addresses[0]), "authority": .string(deviceAuthority(device, fallback: registry.members[deviceMember(device)]?.name))]
  }

  /// `online` while the device's agent is bound, `offline` for a member that isn't, else nil
  func deviceNetworkState(_ device: String) -> String? {
    if agentDevices.values.contains(device) { return "online" }
    return registry.members[deviceMember(device)] != nil ? "offline" : nil
  }

  /// `network/agents/list`: owners and the hub host's agent see every member; others see the agents of shares they
  /// can see, without WireGuard keys
  func listAgents(_ connection: HubConnection) -> [JSON] {
    let localAgentKey = localAgent.machine?.key
    if isOwner(connection) || (connection.key != nil && connection.key == localAgentKey) { return listMembers() }
    var visible = Set(visibleProviders(connection).map(\.key))
    if let key = connection.key, agents.profile(key) != nil { visible.insert(key) }
    return agents.listProfiles.filter { visible.contains($0.key) }.map { profile in
      var object = profile.json.object!
      object["wireGuardKey"] = ""
      return .object(object)
    }
  }

  func agentStatus(_ connection: HubConnection) -> [JSON] {
    if isOwner(connection) { return agents.listAgentStatus }
    let visible = Set(listAgents(connection).compactMap { $0["key"]?.string })
    return agents.listAgentStatus.filter { visible.contains($0["key"]?.string ?? "") }.map { status in
      var object = status.object!
      object["addresses"] = []
      return .object(object)
    }
  }

  /// Removes the member of a removed or revoked device, and legacy members of its revoked keys, releasing their
  /// addresses. Their WireGuard keys go to `network/devices/revoked`, so every agent drops them as peers.
  func removeDevice(_ device: String, revokedKeys: [String]) {
    var wireGuardKeys: [String] = []
    func add(_ key: String) { if !wireGuardKeys.contains(key) { wireGuardKeys.append(key) } }
    for key in [deviceMember(device)] + revokedKeys {
      if let member = registry.removeMember(key) { add(member.wireGuardKey) }
    }
    for (key, agentDevice) in agentDevices where agentDevice == device || revokedKeys.contains(key) {
      if let profile = agents.profile(key) { add(profile.wireGuardKey) }
      agents.unregisterProfile(key)
      agentDevices[key] = nil
    }
    for key in revokedKeys {
      if let profile = agents.profile(key) { add(profile.wireGuardKey) }
      agents.unregisterProfile(key)
    }
    if !wireGuardKeys.isEmpty {
      registry.addRevokedDevice(device: device, wireGuardKeys: wireGuardKeys)
      onRevokedDevicesChanged()
    }
    onStateChanged()
  }

  /// The full revoked list for owners and bound agents
  func revokedDevices(_ connection: HubConnection) -> [JSON] {
    guard isOwner(connection) || (connection.key.map { agents.profile($0) != nil } ?? false) else { return [] }
    return registry.revokedDevices
  }

  func disconnected(_ connection: HubConnection) {
    for (gatewayKey, gateway) in gateways where gateway.connectionId == connection.id {
      _ = revokeGateway(gatewayKey, reason: "provider_disconnected")
    }
    localAgent.disconnect(connection.id)
    agents.clearConnectionProviders(connection.id)
    let removed = agents.unregisterConnection(connection.id)
    for key in removed { agentDevices[key] = nil }
    if let key = connection.key, removed.contains(key) {
      for (resourceId, keys) in grantAgents where keys.contains(key) {
        grantAgents[resourceId]?.remove(key)
        if grantAgents[resourceId]?.isEmpty == true { grantAgents[resourceId] = nil }
      }
    }
    onStateChanged()
  }
}
