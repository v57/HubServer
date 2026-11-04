import ChannelServer
import Foundation

// Device layer, protocol.md sections 1, 3, 5, 6 and 8

/// Longest certificate lifetime, 7 days
let certificateMaxLifetime = 604_800
private let certificateClockSkew = 30
private let platforms: Set<String> = ["macos", "ios", "ipados", "visionos", "tvos", "watchos", "linux", "windows", "android", "other"]

/// A verified `device` header
struct Certificate {
  var device: String
  var deviceId: String
  var service: String
  var instance: String
  var deviceName: String?
  var platform: String?
  var parent: String?
  var iat: Int
  var exp: Int
}

enum CertificateCheck {
  case valid(Certificate)
  case invalid(String)
}

/// Checks a `device` header for the service key in `auth`. An invalid certificate makes a plain key connection.
func verifyCertificate(_ header: String, serviceKey: String, hubKey: String, now: Int = Int(Date().timeIntervalSince1970)) -> CertificateCheck {
  let parts = header.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
  guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return .invalid("malformed certificate") }
  let payload = parts[0], signature = parts[1]
  guard let data = HubCrypto.base64URLDecode(payload), let body = try? JSON.parse(data), body.object != nil else {
    return .invalid("malformed certificate")
  }
  func bytes(_ value: String) -> Int { value.utf8.count }
  func optionalText(_ value: JSON?, max: Int) -> Bool {
    guard let value else { return true }
    guard let text = value.string else { return false }
    return bytes(text) <= max
  }
  guard body["v"]?.int == 1 else { return .invalid("unsupported certificate version") }
  guard let device = body["device"]?.string, let service = body["service"]?.string else { return .invalid("malformed certificate") }
  guard service == serviceKey else { return .invalid("certificate is for another service key") }
  guard let instance = body["instance"]?.string, (1...128).contains(bytes(instance)) else { return .invalid("invalid instance") }
  guard optionalText(body["deviceName"], max: 64), optionalText(body["parent"], max: 64) else { return .invalid("invalid device name or parent") }
  if let platform = body["platform"], platform.string == nil { return .invalid("invalid platform") }
  if let hub = body["hub"], hub.string != hubKey { return .invalid("certificate is for another hub") }
  guard let iat = body["iat"]?.int, let exp = body["exp"]?.int else { return .invalid("invalid times") }
  guard exp - iat <= certificateMaxLifetime else { return .invalid("certificate lifetime too long") }
  guard iat <= now + certificateClockSkew else { return .invalid("certificate issued in the future") }
  guard exp > now - certificateClockSkew else { return .invalid("certificate expired") }
  guard HubCrypto.publicKey(spki: device) != nil else { return .invalid("invalid device key") }
  guard HubCrypto.verify(signature: signature, message: payload, spki: device) else { return .invalid("invalid certificate signature") }
  let platform = body["platform"]?.string.map { platforms.contains($0) ? $0 : "other" }
  return .valid(Certificate(
    device: device, deviceId: HubCrypto.deviceId(spki: device), service: service, instance: instance,
    deviceName: body["deviceName"]?.string, platform: platform, parent: body["parent"]?.string, iat: iat, exp: exp))
}

struct StoredDevice {
  var key: String
  var name: String
  /// An owner renamed it, the device's own suggestions no longer apply
  var nameByOwner = false
  /// What it asked for, when the name it holds differs
  var askedName: String?
  /// What its safety code covers besides its key, picked by the hub. A revoked device from before these may have none.
  var codeValue: String?
  var platform: String?
  var os: String?
  var arch: String?
  var parent: String?
  var approved = false
  var createdAt: String
  var lastSeen: String
  var revoked: String?
  var capabilities: JSON?

  init(key: String, name: String, platform: String?, parent: String?, now: String) {
    self.key = key
    self.name = name
    self.platform = platform
    self.parent = parent
    createdAt = now
    lastSeen = now
  }
  init(_ json: JSON) throws {
    guard let key = json["key"]?.string else { throw ChannelFailure("device without key") }
    self.key = key
    name = json["name"]?.string ?? ""
    nameByOwner = json["nameByOwner"] == .bool(true)
    askedName = json["askedName"]?.string
    codeValue = json["codeValue"]?.string
    platform = json["platform"]?.string
    os = json["os"]?.string
    arch = json["arch"]?.string
    parent = json["parent"]?.string
    approved = json["approved"] == .bool(true)
    createdAt = json["createdAt"]?.string ?? isoNow()
    lastSeen = json["lastSeen"]?.string ?? createdAt
    revoked = json["revoked"]?.string
    capabilities = json["capabilities"]?.object.map { .object($0) }
  }
  var json: JSON {
    var object: JSONObject = ["key": .string(key), "name": .string(name)]
    if nameByOwner { object["nameByOwner"] = true }
    if let askedName { object["askedName"] = .string(askedName) }
    if let codeValue { object["codeValue"] = .string(codeValue) }
    if let platform { object["platform"] = .string(platform) }
    if let os { object["os"] = .string(os) }
    if let arch { object["arch"] = .string(arch) }
    if let parent { object["parent"] = .string(parent) }
    object["approved"] = .bool(approved)
    object["createdAt"] = .string(createdAt)
    object["lastSeen"] = .string(lastSeen)
    object["revoked"] = JSON(revoked)
    if let capabilities { object["capabilities"] = capabilities }
    return .object(object)
  }
}

struct StoredService {
  var device: String
  var instance: String
  var name: String?
  var lastSeen: String
  var previousDevice: String?

  init(device: String, instance: String, name: String?, lastSeen: String, previousDevice: String?) {
    self.device = device
    self.instance = instance
    self.name = name
    self.lastSeen = lastSeen
    self.previousDevice = previousDevice
  }
  init(_ json: JSON) throws {
    guard let device = json["device"]?.string else { throw ChannelFailure("service without device") }
    self.device = device
    instance = json["instance"]?.string ?? ""
    name = json["name"]?.string
    lastSeen = json["lastSeen"]?.string ?? isoNow()
    previousDevice = json["previousDevice"]?.string
  }
  var json: JSON {
    var object: JSONObject = ["device": .string(device), "instance": .string(instance)]
    if let name { object["name"] = .string(name) }
    object["lastSeen"] = .string(lastSeen)
    object["previousDevice"] = JSON(previousDevice)
    return .object(object)
  }
}

/// Most pending requests a hub keeps. A guess against a code has to be on the list when the owner compares.
let maxPendingDevices = 256

/// `devices.json`: devices, where each service key runs, and the keys revoked with a device
final class DeviceRegistry {
  private(set) var devices: [String: StoredDevice] = [:]
  /// Device ids in the order they enrolled
  private(set) var order: [String] = []
  private(set) var services: [String: StoredService] = [:]
  private var serviceOrder: [String] = []
  private(set) var revokedKeys: [String] = []
  let store: JSONStore
  var onChange: () -> Void = {}
  /// The hub's key, which safety codes cover
  let hubKey: String

  init(storage: Storage, hubKey: String) {
    self.hubKey = hubKey
    store = storage.store("devices.json")
    store.encode = { [unowned self] in
      ["schema": 1,
       "devices": .object(JSONObject(order.compactMap { id in devices[id].map { (id, $0.json) } })),
       "services": .object(JSONObject(serviceOrder.compactMap { key in services[key].map { (key, $0.json) } })),
       "revokedKeys": JSON(revokedKeys)]
    }
  }
  func load() {
    store.load { data in
      guard data["schema"]?.int == 1 else { throw ChannelFailure("unsupported devices schema") }
      for (id, device) in data["devices"]?.object ?? [:] {
        devices[id] = try StoredDevice(device)
        order.append(id)
      }
      for (key, service) in data["services"]?.object ?? [:] {
        services[key] = try StoredService(service)
        serviceOrder.append(key)
      }
      revokedKeys = data["revokedKeys"]?.strings ?? []
    }
    if !store.corrupt && settleStored() { store.writeNow() }
  }

  /// Stores from before names were unique and codes covered a value: every device gets a value, and of approved devices
  /// with the same name the one that came first keeps it. Names an owner set stay, even two of the same.
  private func settleStored() -> Bool {
    var changed = false
    for id in order where devices[id]?.codeValue == nil && devices[id]?.revoked == nil {
      devices[id]?.codeValue = HubCrypto.newCodeValue()
      changed = true
    }
    let holders = order.filter { devices[$0]?.approved == true && devices[$0]?.revoked == nil }.sorted { a, b in
      let left = devices[a]!.createdAt, right = devices[b]!.createdAt
      return left == right ? a < b : left < right
    }
    var held = Set(holders.compactMap { id in devices[id]!.nameByOwner ? normalizeName(devices[id]!.name) : nil })
    for id in holders where !devices[id]!.nameByOwner {
      let current = devices[id]!.name
      let name = freeName(current) { held.contains($0) }
      if !name.unicodeScalars.elementsEqual(current.unicodeScalars) {
        devices[id]!.askedName = current
        devices[id]!.name = name
        changed = true
      }
      held.insert(normalizeName(name))
    }
    let pending = pendingIds()
    for id in pending.prefix(max(0, pending.count - maxPendingDevices)) {
      devices[id] = nil
      order.removeAll { $0 == id }
      changed = true
    }
    return changed
  }

  /// The names approved devices hold, normalized, except `id`'s. A pending request or a revoked device holds none.
  private func heldNames(except id: String?) -> [String: String] {
    var held: [String: String] = [:]
    for other in order where other != id {
      guard let device = devices[other], device.approved, device.revoked == nil else { continue }
      held[normalizeName(device.name)] = other
    }
    return held
  }

  private func availableName(for id: String, asked: String) -> String {
    let held = heldNames(except: id)
    return freeName(asked) { held[$0] != nil }
  }

  /// A device suggests a name for itself: a pending one shows what it asks for, an approved one gets a free name
  private func suggest(_ id: String, _ asked: String) {
    guard let device = devices[id], !device.nameByOwner else { return }
    let clean = cleanName(asked)
    if !device.approved {
      devices[id]!.name = clean
    } else if clean != device.askedName ?? device.name {
      devices[id]!.askedName = clean
      devices[id]!.name = availableName(for: id, asked: clean)
    }
  }

  /// Approved from now on: a request gets its final name here
  private func settle(_ id: String) {
    guard let device = devices[id], !device.approved else { return }
    devices[id]!.approved = true
    if device.nameByOwner {
      try? claim(id, device.name)
    } else {
      let name = availableName(for: id, asked: device.name)
      if name != device.name { devices[id]!.askedName = device.name }
      devices[id]!.name = name
    }
  }

  /// An owner's name: a device that only asked for the same one moves to a free name. Against a name an owner set, the
  /// newer one gets the suffix, for an approval that has no one to ask, or `name taken` for a rename.
  private func claim(_ id: String, _ name: String, refuse: Bool = false) throws {
    let holder = heldNames(except: id)[normalizeName(name)]
    if let holder, devices[holder]?.nameByOwner == true {
      if refuse { throw ChannelFailure("name taken") }
      devices[id]!.name = availableName(for: id, asked: name)
      return
    }
    devices[id]!.name = name
    if let holder {
      let asked = devices[holder]!.askedName ?? devices[holder]!.name
      devices[holder]!.askedName = asked
      devices[holder]!.name = availableName(for: holder, asked: asked)
    }
  }
  private func save() {
    store.save()
    onChange()
  }
  func device(_ id: String) -> StoredDevice? { devices[id] }
  func isKeyRevoked(_ key: String) -> Bool { revokedKeys.contains(key) }

  /// A connection with a valid certificate: a new device becomes pending, a known one updates its suggested name and
  /// `lastSeen`. Returns the device, nil when it is revoked.
  func seen(_ certificate: Certificate, approve: Bool) -> StoredDevice? {
    let now = isoNow()
    let id = certificate.deviceId
    if var device = devices[id] {
      if device.revoked != nil { return nil }
      device.lastSeen = now
      if let platform = certificate.platform { device.platform = platform }
      if let parent = certificate.parent { device.parent = parent }
      devices[id] = device
      if let name = certificate.deviceName { suggest(id, name) }
    } else {
      var device = StoredDevice(key: certificate.device, name: cleanName(certificate.deviceName ?? certificate.instance),
        platform: certificate.platform, parent: certificate.parent, now: now)
      device.codeValue = HubCrypto.newCodeValue()
      devices[id] = device
      order.append(id)
    }
    if approve { settle(id) }
    save()
    return devices[id]
  }

  /// Places a service key on an approved device. Returns the device it moved from, if it moved.
  @discardableResult
  func place(_ certificate: Certificate, name: String?) -> String? {
    let current = services[certificate.service]
    let moved = current.flatMap { $0.device != certificate.deviceId ? $0.device : nil }
    if current == nil { serviceOrder.append(certificate.service) }
    services[certificate.service] = StoredService(device: certificate.deviceId, instance: certificate.instance,
      name: name ?? current?.name, lastSeen: isoNow(), previousDevice: moved ?? current?.previousDevice)
    save()
    return moved
  }

  @discardableResult
  func approve(_ id: String?) throws -> StoredDevice {
    let device = try require(id)
    if device.revoked != nil { throw ChannelFailure("device revoked") }
    settle(id!)
    save()
    return devices[id!]!
  }

  func rename(_ id: String?, _ name: JSON?) throws {
    guard let name = name?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty, name.utf8.count <= 64 else {
      throw ChannelFailure("invalid name")
    }
    let device = try require(id)
    let clean = cleanName(name)
    if device.approved {
      try claim(id!, clean, refuse: true)
    } else {
      devices[id!]!.name = clean
    }
    devices[id!]!.nameByOwner = true
    devices[id!]!.askedName = nil
    save()
  }

  /// What the reporter describes
  func update(_ id: String, name: String?, os: String?, arch: String?, capabilities: JSON?) throws {
    _ = try require(id)
    if let name { suggest(id, name) }
    var device = devices[id]!
    if let os { device.os = os }
    if let arch { device.arch = arch }
    if let capabilities { device.capabilities = capabilities }
    devices[id] = device
    save()
  }

  /// Forgets the device and its service placements, it can enrol again. Returns the keys that were placed on it.
  @discardableResult
  func remove(_ id: String?) throws -> [String] {
    _ = try require(id)
    devices[id!] = nil
    order.removeAll { $0 == id }
    let keys = servicesOn(id!)
    for key in keys { services[key] = nil }
    serviceOrder.removeAll { keys.contains($0) }
    save()
    return keys
  }

  /// Keeps a tombstone and revokes the service keys placed on it except `keep`. Returns the revoked keys.
  func revoke(_ id: String?, keep: [String]) throws -> [String] {
    var device = try require(id)
    device.revoked = isoNow()
    device.approved = false
    devices[id!] = device
    let revoked = servicesOn(id!).filter { !keep.contains($0) }
    for key in revoked {
      if !revokedKeys.contains(key) { revokedKeys.append(key) }
      services[key] = nil
    }
    serviceOrder.removeAll { revoked.contains($0) }
    save()
    return revoked
  }

  func servicesOn(_ id: String) -> [String] {
    serviceOrder.filter { services[$0]?.device == id }
  }

  var pending: JSON {
    .array(order.compactMap { id in
      guard let device = devices[id], !device.approved, device.revoked == nil else { return nil }
      var object: JSONObject = ["id": .string(id), "key": .string(device.key), "name": .string(device.name)]
      if let platform = device.platform { object["platform"] = .string(platform) }
      if let parent = device.parent { object["parent"] = .string(parent) }
      let value = codeValue(id)
      object["safetyCode"] = .string(HubCrypto.safetyCode(hubKey: hubKey, key: device.key, codeValue: value))
      object["codeValue"] = .string(value)
      object["firstSeen"] = .string(device.createdAt)
      return .object(object)
    })
  }

  /// Its value, which it keeps once picked
  func codeValue(_ id: String) -> String {
    if let value = devices[id]?.codeValue { return value }
    let value = HubCrypto.newCodeValue()
    devices[id]?.codeValue = value
    return value
  }

  /// The ids of pending requests, oldest first
  func pendingIds() -> [String] {
    order.filter { devices[$0]?.approved == false && devices[$0]?.revoked == nil }.sorted { devices[$0]!.createdAt < devices[$1]!.createdAt }
  }

  private func require(_ id: String?) throws -> StoredDevice {
    guard let id, let device = devices[id] else { throw ChannelFailure("device not found") }
    return device
  }
}

/// A connection that asks to be approved and waits its turn
struct WaitingRequest {
  var certificate: Certificate
  var connection: HubConnection
  var deviceId: String { certificate.deviceId }
}

/// The one way a new device gets on the pending list: one request a second for the whole hub, sources taking turns, so
/// rotating addresses doesn't buy guesses and one flooding address doesn't push others out. A flood delays a real
/// request. What waits is bounded; a request beyond that isn't queued, and the connection asks again when its stream
/// recomputes or it reconnects. Confined to the hub's queue.
final class RequestGate {
  private static let maxWaitingPerSource = 8
  private static let maxWaitingSources = 4096
  /// Seconds between requests
  var interval: TimeInterval = 1
  /// Sources, whose turn is next first
  private var sources: [String] = []
  private var waiting: [String: [WaitingRequest]] = [:]
  private var lastAdmission: TimeInterval = -.infinity
  private var timerSet = false
  private let queue: DispatchQueue
  var admit: (WaitingRequest) -> Void = { _ in }

  init(queue: DispatchQueue) {
    self.queue = queue
  }

  func has(_ deviceId: String) -> Bool {
    waiting.values.contains { $0.contains { $0.deviceId == deviceId } }
  }

  /// Queues a request, once per device. Admits at once while the hub is idle.
  func ask(_ source: String, _ request: WaitingRequest) {
    if has(request.deviceId) { return }
    if let queued = waiting[source] {
      if queued.count >= Self.maxWaitingPerSource { return }
      waiting[source]!.append(request)
    } else {
      if sources.count >= Self.maxWaitingSources { return }
      waiting[source] = [request]
      sources.append(source)
    }
    next()
  }

  /// Forgets what `matches` picks: its connection went, or it needs no turn any more
  func forget(_ matches: (WaitingRequest) -> Bool) {
    for (source, requests) in waiting {
      let left = requests.filter { !matches($0) }
      if left.isEmpty {
        waiting[source] = nil
        sources.removeAll { $0 == source }
      } else {
        waiting[source] = left
      }
    }
  }

  private func next() {
    guard !timerSet, let source = sources.first else { return }
    let wait = lastAdmission + interval - ProcessInfo.processInfo.systemUptime
    if wait > 0 {
      timerSet = true
      queue.asyncAfter(deadline: .now() + wait) { [weak self] in
        self?.timerSet = false
        self?.next()
      }
      return
    }
    var requests = waiting[source]!
    let request = requests.removeFirst()
    // The source goes to the end of the line
    sources.removeFirst()
    if requests.isEmpty {
      waiting[source] = nil
    } else {
      waiting[source] = requests
      sources.append(source)
    }
    lastAdmission = ProcessInfo.processInfo.systemUptime
    admit(request)
    next()
  }
}

/// The address a request counts against: IPv4, or the /64 of IPv6, which is what one host usually has. Behind a proxy
/// every request has the proxy's address, so they share one turn; the hub trusts no forwarded header, as a client could
/// send any, and the limit for the whole hub holds either way. A host that gives no address shares one turn too.
func requestSource(_ address: String?) -> String {
  guard let address, !address.isEmpty else { return "unknown" }
  let plain = String(address.split(separator: "%", omittingEmptySubsequences: false)[0]).lowercased()
  if plain.hasPrefix("::ffff:"), plain.contains(".") { return String(plain.dropFirst(7)) }
  if !plain.contains(":") { return plain }
  let parts = plain.components(separatedBy: "::")
  let leading = parts[0].isEmpty ? [] : parts[0].components(separatedBy: ":")
  let trailing = parts.count > 1 && !parts[1].isEmpty ? parts[1].components(separatedBy: ":") : []
  let groups = leading + Array(repeating: "0", count: max(0, 8 - leading.count - trailing.count)) + trailing
  return groups.prefix(4).map { String(Int($0, radix: 16) ?? 0, radix: 16) }.joined(separator: ":") + "::/64"
}
