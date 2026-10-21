import ChannelServer
import Foundation

/// A 128-bit address (IPv4 in the low 32 bits), stored as a decimal string like hub-server's BigInt
struct OverlayAddress: Comparable, Hashable {
  var hi: UInt64
  var lo: UInt64

  init(hi: UInt64 = 0, lo: UInt64) {
    self.hi = hi
    self.lo = lo
  }

  init?(decimal: String) {
    guard !decimal.isEmpty, decimal.allSatisfy(\.isASCII) else { return nil }
    var value = OverlayAddress(lo: 0)
    for character in decimal {
      guard let digit = character.wholeNumberValue else { return nil }
      // value = value * 10 + digit
      let low = value.lo.multipliedFullWidth(by: 10)
      let high = value.hi.multipliedReportingOverflow(by: 10)
      guard !high.overflow else { return nil }
      let (hiSum, hiOverflow) = high.partialValue.addingReportingOverflow(low.high)
      guard !hiOverflow else { return nil }
      let (loSum, carry) = low.low.addingReportingOverflow(UInt64(digit))
      let (hiFinal, overflow) = hiSum.addingReportingOverflow(carry ? 1 : 0)
      guard !overflow else { return nil }
      value = OverlayAddress(hi: hiFinal, lo: loSum)
    }
    self = value
  }

  var decimal: String {
    if hi == 0 { return String(lo) }
    var digits: [Character] = []
    var current = self
    while current.hi != 0 || current.lo != 0 {
      // Divide by 10, keeping the remainder
      let (qHi, rHi) = current.hi.quotientAndRemainder(dividingBy: 10)
      let (qLo, rLo) = UInt64(10).dividingFullWidth((high: rHi, low: current.lo))
      digits.append(Character(String(rLo)))
      current = OverlayAddress(hi: qHi, lo: qLo)
    }
    return String(digits.reversed())
  }

  init?(ip: String) {
    if ip.contains(".") {
      let parts = ip.split(separator: ".").compactMap { UInt64($0) }
      guard parts.count == 4, parts.allSatisfy({ $0 < 256 }) else { return nil }
      self.init(lo: parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3])
      return
    }
    var hextets: [UInt64] = []
    let halves = ip.components(separatedBy: "::")
    guard halves.count <= 2 else { return nil }
    func parse(_ text: String) -> [UInt64]? {
      text.isEmpty ? [] : text.split(separator: ":", omittingEmptySubsequences: false).map { UInt64($0, radix: 16) ?? .max }
    }
    guard let head = parse(halves[0]) else { return nil }
    if halves.count == 2 {
      guard let tail = parse(halves[1]), head.count + tail.count < 8 else { return nil }
      hextets = head + Array(repeating: 0, count: 8 - head.count - tail.count) + tail
    } else {
      hextets = head
    }
    guard hextets.count == 8, hextets.allSatisfy({ $0 <= 0xFFFF }) else { return nil }
    self.init(hi: hextets[0] << 48 | hextets[1] << 32 | hextets[2] << 16 | hextets[3],
      lo: hextets[4] << 48 | hextets[5] << 32 | hextets[6] << 16 | hextets[7])
  }

  /// IPv4 dotted for values up to 32 bits, else IPv6 with the longest zero run (of two or more) compressed
  var ip: String {
    if hi == 0, lo <= 0xFFFF_FFFF {
      return "\(lo >> 24 & 0xFF).\(lo >> 16 & 0xFF).\(lo >> 8 & 0xFF).\(lo & 0xFF)"
    }
    let hextets = [hi >> 48, hi >> 32 & 0xFFFF, hi >> 16 & 0xFFFF, hi & 0xFFFF, lo >> 48, lo >> 32 & 0xFFFF, lo >> 16 & 0xFFFF, lo & 0xFFFF]
    var bestStart = -1, bestLength = 0, start = -1, length = 0
    for (index, hextet) in hextets.enumerated() {
      if hextet == 0 {
        if start == -1 { start = index }
        length += 1
      } else {
        if length > bestLength {
          bestStart = start
          bestLength = length
        }
        start = -1
        length = 0
      }
    }
    if length > bestLength {
      bestStart = start
      bestLength = length
    }
    let text = hextets.map { String($0, radix: 16) }
    guard bestLength > 1 else { return text.joined(separator: ":") }
    return text[..<bestStart].joined(separator: ":") + "::" + text[(bestStart + bestLength)...].joined(separator: ":")
  }

  var next: OverlayAddress {
    lo == .max ? OverlayAddress(hi: hi &+ 1, lo: 0) : OverlayAddress(hi: hi, lo: lo + 1)
  }

  static func < (left: OverlayAddress, right: OverlayAddress) -> Bool {
    left.hi != right.hi ? left.hi < right.hi : left.lo < right.lo
  }
}

/// A member's last bound WireGuard key and labels, kept while it is offline. Stored by member key: `device:<id>`
/// for device-attached agents, else the agent's service key.
struct StoredMember: Equatable {
  /// The agent's service key, when it differs from the member key
  var key: String?
  var device: String?
  var wireGuardKey: String
  var name: String?
  var platform: String?
  var lastSeen: String

  init(key: String? = nil, device: String? = nil, wireGuardKey: String, name: String?, platform: String?, lastSeen: String) {
    self.key = key
    self.device = device
    self.wireGuardKey = wireGuardKey
    self.name = name
    self.platform = platform
    self.lastSeen = lastSeen
  }
  init?(_ json: JSON) {
    guard let wireGuardKey = json["wireGuardKey"]?.string else { return nil }
    self.init(key: json["key"]?.string, device: json["device"]?.string, wireGuardKey: wireGuardKey,
      name: json["name"]?.string, platform: json["platform"]?.string, lastSeen: json["lastSeen"]?.string ?? isoNow())
  }
  var json: JSON {
    var object = JSONObject()
    if let key { object["key"] = .string(key) }
    if let device { object["device"] = .string(device) }
    object["wireGuardKey"] = .string(wireGuardKey)
    if let name { object["name"] = .string(name) }
    if let platform { object["platform"] = .string(platform) }
    object["lastSeen"] = .string(lastSeen)
    return .object(object)
  }
}

/// A share's stable identity and policy
struct NetworkResource {
  var resourceId: String
  var ownerKey: String
  var shareName: String
  var authority: String
  var policy: JSON
  var generation: Int

  init(resourceId: String, ownerKey: String, shareName: String, authority: String, policy: JSON, generation: Int) {
    self.resourceId = resourceId
    self.ownerKey = ownerKey
    self.shareName = shareName
    self.authority = authority
    self.policy = policy
    self.generation = generation
  }
  init?(_ json: JSON) {
    guard let resourceId = json["resourceId"]?.string, let ownerKey = json["ownerKey"]?.string else { return nil }
    self.init(resourceId: resourceId, ownerKey: ownerKey, shareName: json["shareName"]?.string ?? "",
      authority: json["authority"]?.string ?? "", policy: json["policy"] ?? ["mode": "private"], generation: json["generation"]?.int ?? 0)
  }
  var json: JSON {
    ["version": .int(NetworkFoundation.wireVersion), "resourceId": .string(resourceId), "ownerKey": .string(ownerKey),
     "shareName": .string(shareName), "authority": .string(authority), "policy": policy, "generation": .int(generation)]
  }
  var mode: String { policy["mode"]?.string ?? "private" }
}

/// `network.json`: the network's identity, overlay address allocations, members, shares (resources) and revoked
/// devices. A corrupt file leaves the registry empty and read-only.
final class NetworkRegistry {
  static let schemaVersion = 1
  static let releasedHold: TimeInterval = 24 * 60 * 60

  private(set) var hubNetworkId = ""
  private(set) var hubKey = ""
  var nextIPv4 = OverlayAddress(ip: NetworkFoundation.ipv4First)!
  var lastIPv4 = OverlayAddress(ip: NetworkFoundation.ipv4Last)!
  var nextIPv6 = OverlayAddress(ip: NetworkFoundation.ipv6First)!
  var lastIPv6 = OverlayAddress(ip: NetworkFoundation.ipv6Last)!
  private(set) var resources: [String: NetworkResource] = [:]
  private(set) var resourceOrder: [String] = []
  private(set) var allocations: [String: [String]] = [:]
  private var allocationOrder: [String] = []
  private(set) var members: [String: StoredMember] = [:]
  private var memberOrder: [String] = []
  /// Addresses of removed members, reused a day later once the range runs out
  var released: [(addresses: [String], at: String)] = []
  /// WireGuard keys of removed and revoked devices, for `network/devices/revoked`
  private(set) var revokedDevices: [JSON] = []
  /// Fields hub-server may add, kept as they are
  private var extra = JSONObject()
  let store: JSONStore

  init(storage: Storage) {
    store = storage.store("network.json")
    store.encode = { [unowned self] in encode() }
  }

  var corrupt: Bool { store.corrupt }

  func load() {
    var needsWrite = false
    store.load { json in
      guard let object = json.object else { throw ChannelFailure("not an object") }
      extra = object
      hubNetworkId = object["hubNetworkId"]?.string ?? ""
      hubKey = object["hubKey"]?.string ?? ""
      func address(_ key: String, _ fallback: OverlayAddress) -> OverlayAddress {
        object[key]?.string.flatMap(OverlayAddress.init(decimal:)) ?? fallback
      }
      nextIPv4 = address("nextIPv4", nextIPv4)
      lastIPv4 = address("lastIPv4", lastIPv4)
      nextIPv6 = address("nextIPv6", nextIPv6)
      lastIPv6 = address("lastIPv6", lastIPv6)
      for (id, value) in object["resources"]?.object ?? [:] {
        guard let resource = NetworkResource(value) else { continue }
        resources[id] = resource
        resourceOrder.append(id)
      }
      var seen: [String: String] = [:]
      for (key, value) in object["allocations"]?.object ?? [:] {
        guard let addresses = value.strings, addresses.count == 2, !addresses[0].isEmpty, !addresses[1].isEmpty else {
          throw ChannelFailure("invalid overlay allocation for \(key)")
        }
        for address in addresses {
          if let owner = seen[address], owner != key { throw ChannelFailure("duplicate overlay allocation: \(address)") }
          seen[address] = key
        }
        allocations[key] = addresses
        allocationOrder.append(key)
      }
      for (key, value) in object["members"]?.object ?? [:] {
        guard let member = StoredMember(value) else { continue }
        members[key] = member
        memberOrder.append(key)
      }
      released = (object["released"]?.array ?? []).compactMap { entry in
        guard let addresses = entry["addresses"]?.strings, let at = entry["at"]?.string else { return nil }
        return (addresses, at)
      }
      revokedDevices = object["revokedDevices"]?.array ?? []
      needsWrite = object["schemaVersion"]?.int != NetworkRegistry.schemaVersion
    }
    // A corrupt registry stays empty and read-only: no identity, no new members
    guard !store.corrupt else { return }
    if hubNetworkId.isEmpty {
      hubNetworkId = newId()
      needsWrite = true
    }
    if needsWrite { store.writeNow() }
  }

  private func encode() -> JSON {
    var object = extra
    object["schemaVersion"] = .int(NetworkRegistry.schemaVersion)
    object["hubNetworkId"] = .string(hubNetworkId)
    object["hubKey"] = .string(hubKey)
    object["nextIPv4"] = .string(nextIPv4.decimal)
    object["lastIPv4"] = .string(lastIPv4.decimal)
    object["nextIPv6"] = .string(nextIPv6.decimal)
    object["lastIPv6"] = .string(lastIPv6.decimal)
    object["resources"] = .object(JSONObject(resourceOrder.compactMap { id in resources[id].map { (id, $0.json) } }))
    object["allocations"] = .object(JSONObject(allocationOrder.compactMap { key in allocations[key].map { (key, JSON($0)) } }))
    object["members"] = .object(JSONObject(memberOrder.compactMap { key in members[key].map { (key, $0.json) } }))
    object["released"] = .array(released.map { ["addresses": JSON($0.addresses), "at": .string($0.at)] })
    object["revokedDevices"] = .array(revokedDevices)
    return .object(object)
  }

  func setHubKey(_ key: String) {
    guard hubKey != key, !store.corrupt else { return }
    hubKey = key
    store.save()
  }

  // MARK: Addresses

  func hasAllocation(_ key: String) -> Bool { allocations[key] != nil }

  /// One IPv4 and one IPv6 overlay address for the member, the same ones on every call
  func allocateAddresses(_ key: String) throws -> (ipv4: String, ipv6: String) {
    guard !key.isEmpty else { throw ChannelFailure("profile key is required") }
    guard !store.corrupt else { throw ChannelFailure("network registry is corrupt") }
    if let existing = allocations[key] { return (existing[0], existing[1]) }
    let usedIPv4 = Set(allocations.values.map { $0[0] })
    let usedIPv6 = Set(allocations.values.map { $0[1] })
    var ipv4 = nextIPv4
    var ipv6 = nextIPv6
    while ipv4 <= lastIPv4, usedIPv4.contains(ipv4.ip) { ipv4 = ipv4.next }
    while ipv6 <= lastIPv6, usedIPv6.contains(ipv6.ip) { ipv6 = ipv6.next }
    if ipv4 > lastIPv4 || ipv6 > lastIPv6 {
      if let reused = reuseReleased(key) { return reused }
      throw ChannelFailure("overlay address exhausted")
    }
    nextIPv4 = ipv4.next
    nextIPv6 = ipv6.next
    setAllocation(key, [ipv4.ip, ipv6.ip])
    store.save()
    return (ipv4.ip, ipv6.ip)
  }

  private func setAllocation(_ key: String, _ addresses: [String]?) {
    if let addresses {
      if allocations.updateValue(addresses, forKey: key) == nil { allocationOrder.append(key) }
    } else if allocations.removeValue(forKey: key) != nil {
      allocationOrder.removeAll { $0 == key }
    }
  }

  private func setMember(_ key: String, _ member: StoredMember?) {
    if let member {
      if members.updateValue(member, forKey: key) == nil { memberOrder.append(key) }
    } else if members.removeValue(forKey: key) != nil {
      memberOrder.removeAll { $0 == key }
    }
  }

  /// Addresses released more than a day ago, once the range is used up
  private func reuseReleased(_ key: String) -> (ipv4: String, ipv6: String)? {
    let cutoff = Date().addingTimeInterval(-NetworkRegistry.releasedHold)
    guard let index = released.firstIndex(where: { (NetworkTime.parse($0.at) ?? .distantFuture) <= cutoff }) else { return nil }
    let entry = released.remove(at: index)
    setAllocation(key, entry.addresses)
    store.save()
    return (entry.addresses[0], entry.addresses[1])
  }

  // MARK: Members

  /// Moves a legacy member keyed by its service key to its device member key, keeping its addresses
  func moveMember(from: String, to: String) {
    guard from != to, let addresses = allocations[from], allocations[to] == nil else { return }
    setAllocation(to, addresses)
    setAllocation(from, nil)
    if let member = members[from] {
      setMember(to, member)
      setMember(from, nil)
    }
    store.save()
  }

  /// Forgets a member and releases its addresses for reuse after a day. Returns the stored member.
  @discardableResult
  func removeMember(_ key: String) -> StoredMember? {
    let member = members[key]
    let addresses = allocations[key]
    setMember(key, nil)
    setAllocation(key, nil)
    if let addresses { released.append((addresses, isoNow())) }
    if member != nil || addresses != nil { store.save() }
    return member
  }

  func addRevokedDevice(device: String, wireGuardKeys: [String]) {
    revokedDevices.removeAll { $0["device"]?.string == device }
    revokedDevices.append(["device": .string(device), "wireGuardKeys": JSON(wireGuardKeys), "at": .string(isoNow())])
    store.save()
  }

  /// A removed device that enrolled again is no longer refused as a peer
  func clearRevokedDevice(_ device: String) -> Bool {
    let count = revokedDevices.count
    revokedDevices.removeAll { $0["device"]?.string == device }
    guard revokedDevices.count != count else { return false }
    store.save()
    return true
  }

  /// Records the member's current WireGuard key so its peer survives restarts
  func rememberMember(_ key: String, _ member: StoredMember) {
    if var previous = members[key], previous.wireGuardKey == member.wireGuardKey, previous.name == member.name,
      previous.platform == member.platform, previous.key == member.key
    {
      previous.lastSeen = member.lastSeen
      members[key] = previous
      return
    }
    setMember(key, member)
    store.save()
  }

  /// Members with a stored WireGuard key and an allocation
  func listMembers() -> [(key: String, member: StoredMember, addresses: [String])] {
    memberOrder.compactMap { key in
      guard let member = members[key], let addresses = allocations[key] else { return nil }
      return (key, member, addresses)
    }
  }

  // MARK: Resources

  func registerResource(_ resource: NetworkResource) throws {
    if let existing = resources[resource.resourceId], existing.ownerKey != resource.ownerKey {
      throw ChannelFailure("resource_id_collision")
    }
    if resources.updateValue(resource, forKey: resource.resourceId) == nil { resourceOrder.append(resource.resourceId) }
    store.save()
  }

  func resource(_ id: String) -> NetworkResource? { resources[id] }

  var allResources: [NetworkResource] { resourceOrder.compactMap { resources[$0] } }

  func updateResource(_ id: String, policy: JSON, generation: Int) throws {
    guard var resource = resources[id] else { throw ChannelFailure("resource not found") }
    resource.policy = policy
    resource.generation = generation
    resources[id] = resource
    store.save()
  }

  @discardableResult
  func incrementGeneration(_ id: String) throws -> Int {
    guard var resource = resources[id] else { throw ChannelFailure("resource not found") }
    resource.generation += 1
    resources[id] = resource
    store.save()
    return resource.generation
  }
}

/// A connected agent, as `hub/net/bind` returns it and member lists show it
struct AgentProfile {
  var wireGuardKey: String
  var name: String?
  var platform: String?
  /// The agent's service key
  var key: String
  /// `device:<id>` for device-attached agents, else the service key
  var member: String?
  var device: String?
  var overlayAddresses: [String]
  var connectedAt: String

  var json: JSON {
    var object: JSONObject = ["version": .int(NetworkFoundation.wireVersion), "wireGuardKey": .string(wireGuardKey)]
    if let name { object["name"] = .string(name) }
    if let platform { object["platform"] = .string(platform) }
    object["key"] = .string(key)
    if let member { object["member"] = .string(member) }
    if let device { object["device"] = .string(device) }
    object["overlayAddresses"] = JSON(overlayAddresses)
    object["connectedAt"] = .string(connectedAt)
    return .object(object)
  }
}

/// A service connection publishing a share through an agent
struct LiveProvider {
  var providerId: String
  var resourceId: String
  var serviceKey: String
  var key: String
  var `protocol`: String
  var overlayAddress: String
  var port: Int
  var connectedAt: String

  var json: JSON {
    ["version": .int(NetworkFoundation.wireVersion), "providerId": .string(providerId), "resourceId": .string(resourceId),
     "serviceKey": .string(serviceKey), "key": .string(key), "protocol": .string(`protocol`), "overlayAddress": .string(overlayAddress),
     "port": .int(port), "connectedAt": .string(connectedAt)]
  }
}

/// Agents and live providers, which exist only while their connections do
final class AgentRegistry {
  private(set) var profiles: [String: AgentProfile] = [:]
  private var profileOrder: [String] = []
  private var connectionAgents: [String: Set<String>] = [:]
  private var agentConnections: [String: Set<String>] = [:]
  private var connectionProviders: [String: Set<String>] = [:]
  private(set) var providers: [String: LiveProvider] = [:]
  private var providerOrder: [String] = []
  private(set) var agentStatus: [String: JSON] = [:]
  /// Latest generation snapshot staged for each connected agent, per resource
  private var stagedGenerations: [String: [String: JSON]] = [:]

  func profile(_ key: String) -> AgentProfile? { profiles[key] }
  var listProfiles: [AgentProfile] { profileOrder.compactMap { profiles[$0] } }
  var listProviders: [LiveProvider] { providerOrder.compactMap { providers[$0] } }
  var listAgentStatus: [JSON] { profileOrder.compactMap { agentStatus[$0] } }

  func registerProfile(_ profile: AgentProfile, connectionId: String?) {
    if profiles.updateValue(profile, forKey: profile.key) == nil { profileOrder.append(profile.key) }
    if let connectionId {
      connectionAgents[connectionId, default: []].insert(profile.key)
      agentConnections[profile.key, default: []].insert(connectionId)
    }
    agentStatus[profile.key] = ["version": .int(NetworkFoundation.wireVersion), "key": .string(profile.key), "available": true,
      "addresses": JSON(profile.overlayAddresses), "peers": 0, "shares": 0, "updatedAt": .string(isoNow())]
  }

  func unregisterProfile(_ key: String) {
    for connectionId in agentConnections.removeValue(forKey: key) ?? [] {
      connectionAgents[connectionId]?.remove(key)
      if connectionAgents[connectionId]?.isEmpty == true { connectionAgents[connectionId] = nil }
    }
    guard profiles.removeValue(forKey: key) != nil else { return }
    profileOrder.removeAll { $0 == key }
    agentStatus[key] = nil
    stagedGenerations[key] = nil
    for provider in listProviders where provider.key == key { removeProvider(provider.providerId) }
  }

  /// Removes only the profiles the disconnected connection registered. Returns their keys.
  func unregisterConnection(_ connectionId: String) -> Set<String> {
    var removed = Set<String>()
    for key in connectionAgents.removeValue(forKey: connectionId) ?? [] {
      agentConnections[key]?.remove(connectionId)
      if agentConnections[key]?.isEmpty == false { continue }
      agentConnections[key] = nil
      unregisterProfile(key)
      removed.insert(key)
    }
    return removed
  }

  func registerProvider(_ provider: LiveProvider, connectionId: String?) {
    if providers.updateValue(provider, forKey: provider.providerId) == nil { providerOrder.append(provider.providerId) }
    if let connectionId { connectionProviders[connectionId, default: []].insert(provider.providerId) }
    updateShareCount(provider.key)
  }

  func removeProvider(_ providerId: String) {
    guard let provider = providers.removeValue(forKey: providerId) else { return }
    providerOrder.removeAll { $0 == providerId }
    updateShareCount(provider.key)
    for (connectionId, ids) in connectionProviders where ids.contains(providerId) {
      connectionProviders[connectionId]?.remove(providerId)
      if connectionProviders[connectionId]?.isEmpty == true { connectionProviders[connectionId] = nil }
    }
  }

  private func updateShareCount(_ key: String) {
    guard var status = agentStatus[key]?.object else { return }
    status["shares"] = .int(providers.values.filter { $0.key == key }.count)
    status["updatedAt"] = .string(isoNow())
    agentStatus[key] = .object(status)
  }

  /// Removes the providers a disconnected or republishing service connection published
  func clearConnectionProviders(_ connectionId: String) {
    for providerId in connectionProviders.removeValue(forKey: connectionId) ?? [] { removeProvider(providerId) }
  }

  func providers(of resourceId: String) -> [LiveProvider] {
    listProviders.filter { $0.resourceId == resourceId }
  }

  /// The requested provider, else the one connected first
  func selectProvider(_ resourceId: String, preferred: String?) -> LiveProvider? {
    let candidates = providers(of: resourceId)
    if let preferred { return candidates.first { $0.providerId == preferred } }
    return candidates.min { left, right in
      left.connectedAt != right.connectedAt ? left.connectedAt < right.connectedAt : left.providerId < right.providerId
    }
  }

  func stageGeneration(_ key: String, _ snapshot: JSON) {
    guard let resourceId = snapshot["resourceId"]?.string else { return }
    stagedGenerations[key, default: [:]][resourceId] = snapshot
  }

  func staged(_ key: String) -> [JSON] {
    (stagedGenerations[key] ?? [:]).sorted { $0.key < $1.key }.map(\.value)
  }
}

/// Validates a share policy: `hub`, `group` (with a group), `keys` (with at least one), `private` or `disabled`
func validateNetworkPolicy(_ policy: JSON?) throws {
  guard let mode = policy?["mode"]?.string, ["hub", "group", "keys", "private", "disabled"].contains(mode) else {
    throw ChannelFailure("invalid policy")
  }
  if mode == "group", (policy?["group"]?.string ?? "").isEmpty { throw ChannelFailure("group policy requires group name") }
  if mode == "keys", (policy?["keys"]?.strings ?? []).isEmpty { throw ChannelFailure("keys policy requires at least one key") }
}
