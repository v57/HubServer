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

  init(storage: Storage) {
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
      if let name = certificate.deviceName, !device.nameByOwner { device.name = name }
      if let platform = certificate.platform { device.platform = platform }
      if let parent = certificate.parent { device.parent = parent }
      if approve { device.approved = true }
      devices[id] = device
    } else {
      var device = StoredDevice(key: certificate.device, name: certificate.deviceName ?? certificate.instance,
        platform: certificate.platform, parent: certificate.parent, now: now)
      device.approved = approve
      devices[id] = device
      order.append(id)
    }
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
    var device = try require(id)
    if device.revoked != nil { throw ChannelFailure("device revoked") }
    device.approved = true
    devices[id!] = device
    save()
    return device
  }

  func rename(_ id: String?, _ name: JSON?) throws {
    guard let name = name?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty, name.utf8.count <= 64 else {
      throw ChannelFailure("invalid name")
    }
    var device = try require(id)
    device.name = name
    device.nameByOwner = true
    devices[id!] = device
    save()
  }

  /// What the reporter describes
  func update(_ id: String, name: String?, os: String?, arch: String?, capabilities: JSON?) throws {
    var device = try require(id)
    if let name, !device.nameByOwner { device.name = name }
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
      object["safetyCode"] = .string(HubCrypto.safetyCode(spki: device.key))
      object["firstSeen"] = .string(device.createdAt)
      return .object(object)
    })
  }

  private func require(_ id: String?) throws -> StoredDevice {
    guard let id, let device = devices[id] else { throw ChannelFailure("device not found") }
    return device
  }
}
