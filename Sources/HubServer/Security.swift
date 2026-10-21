import ChannelServer
import Foundation

// Access control, protocol.md sections 2, 4, 6, 7 and 9

enum SecurityMode: String {
  case defaultAllow = "default-allow"
  case defaultDeny = "default-deny"
}

/// Who may call a built-in API (protocol.md section 7). `own`: `network/*` checks its callers itself.
enum BuiltinAccess {
  case open, auth, reporter, grant, owner, own
}

private let publicBuiltins: Set<String> = [
  "hub/info", "hub/profile/update", "hub/service/update", "hub/api", "hub/status", "hub/status/badges",
  "hub/proxy/join", "hub/header",
]
// `hub/net/bind` keeps the proof of its bind kind, `hub/net/node` tells agents where their node is, `hub/pair`
// takes any keyed caller (section 12)
private let authBuiltins: Set<String> = ["hub/api/services", "hub/net/bind", "hub/net/node", "hub/pair", "hub/grant/check"]
private let reporterBuiltins: Set<String> = ["hub/device/describe", "hub/device/data"]
private let grantBuiltins: Set<String> = ["hub/devices", "hub/devices/data"]

/// Access of a built-in path, nil for service paths
func builtinAccess(_ path: String) -> BuiltinAccess? {
  if path == "network" || path.hasPrefix("network/") { return .own }
  guard path == "hub" || path.hasPrefix("hub/") else { return nil }
  if publicBuiltins.contains(path) { return .open }
  if authBuiltins.contains(path) { return .auth }
  if reporterBuiltins.contains(path) { return .reporter }
  if grantBuiltins.contains(path) { return .grant }
  return .owner
}

/// Names of the owner APIs that `hub/group/names` lists, as hub-server has them
private let hubApiNames: [(String, String)] = [
  ("hub/merge/add", "Hub: Merge Hubs"), ("hub/merge/remove", "Hub: Merge Hubs"), ("hub/key", "Hub: Merge Hubs"),
  ("hub/proxy/add", "Hub: Add Proxy Hubs"), ("hub/proxy/remove", "Hub: Add Proxy Hubs"),
  ("hub/balancer/set", "Hub: Manage Load Balancer"), ("hub/balancer/limit", "Hub: Manage Load Balancer"),
  ("hub/whitelist", "Hub: Whitelist mode"), ("hub/host/update", "Hub: Manage Permissions"),
  ("hub/host/pending", "Hub: Manage Permissions"), ("hub/host/allowed", "Hub: Manage Permissions"),
  ("hub/call/update", "Hub: Manage Permissions"), ("hub/call/pending", "Hub: Manage Permissions"),
  ("hub/call/allowed", "Hub: Manage Permissions"), ("hub/group/create", "Hub: Manage Permissions"),
  ("hub/group/rename", "Hub: Manage Permissions"), ("hub/group/remove", "Hub: Manage Permissions"),
  ("hub/group/update", "Hub: Manage Permissions"), ("hub/group/update/users", "Hub: Manage Permissions"),
  ("hub/header/set", "Hub: Update Header"),
]

let ownersGroup = "owners"
func keyMember(_ key: String) -> String { "key:\(key)" }
func deviceMember(_ id: String) -> String { "device:\(id)" }
/// `key:<SPKI>`, `device:<id>`, or a plain SPKI meaning `key:`
func memberString(_ value: String) -> String {
  value.hasPrefix("key:") || value.hasPrefix("device:") ? value : keyMember(value)
}

/// A connection's identity: its key and, when device-attached, its device id
struct Principal: Hashable {
  var key: String?
  var device: String?
}

/// The caller as services see it in `context.hub.caller`
struct Caller {
  var key: String?
  var device: (id: String, name: String)?
  var groups: [String]
  var owner: Bool

  var json: JSON {
    var object = JSONObject()
    if let key { object["key"] = .string(key) }
    if let device { object["device"] = ["id": .string(device.id), "name": .string(device.name)] }
    object["groups"] = JSON(groups)
    object["owner"] = .bool(owner)
    return .object(object)
  }
}

/// Hub errors with a code (protocol.md section 11); the message stays the string older clients compare
extension ChannelFailure {
  /// No key (anonymous caller) where one is needed
  static let unauthorized = ChannelFailure("unauthorized", code: "unauthorized")
  /// The caller may not call this path
  static let forbidden = ChannelFailure("permissions required", code: "forbidden")
}

// MARK: - Grants

enum GrantSubject: Equatable {
  case key(String), device(String), group(String), everyone

  init(_ value: JSON?) throws {
    guard let object = value?.object else { throw ChannelFailure("invalid subject") }
    if let key = object["key"]?.string, !key.isEmpty {
      self = .key(key)
    } else if let device = object["device"]?.string, !device.isEmpty {
      self = .device(device)
    } else if let group = object["group"]?.string, !group.isEmpty {
      self = .group(group)
    } else if object["everyone"] == .bool(true) {
      self = .everyone
    } else {
      throw ChannelFailure("invalid subject")
    }
  }
  var json: JSON {
    switch self {
    case .key(let key): ["key": .string(key)]
    case .device(let device): ["device": .string(device)]
    case .group(let group): ["group": .string(group)]
    case .everyone: ["everyone": true]
    }
  }
  func matches(_ caller: Caller) -> Bool {
    switch self {
    case .everyone: true
    case .key(let key): key == caller.key
    case .device(let device): device == caller.device?.id
    case .group(let group): caller.groups.contains(group)
    }
  }
}

enum GrantObject: Equatable {
  case path(String), prefix(String), share(String)

  init(_ value: JSON?) throws {
    guard let object = value?.object else { throw ChannelFailure("invalid object") }
    if let path = object["path"]?.string, !path.isEmpty {
      self = .path(path)
    } else if let prefix = object["prefix"]?.string, !prefix.isEmpty {
      self = .prefix(prefix)
    } else if let share = object["share"]?.string, !share.isEmpty {
      self = .share(share)
    } else {
      throw ChannelFailure("invalid object")
    }
  }
  var json: JSON {
    switch self {
    case .path(let path): ["path": .string(path)]
    case .prefix(let prefix): ["prefix": .string(prefix)]
    case .share(let share): ["share": .string(share)]
    }
  }
}

struct Grant {
  var id: String
  var subject: GrantSubject
  var object: GrantObject
  /// Key of the owner who added it
  var by: String
  var at: String

  var json: JSON {
    ["id": .string(id), "subject": subject.json, "object": object.json, "by": .string(by), "at": .string(at)]
  }
}

/// `grants.json`: who may call which paths
final class GrantStore {
  private(set) var grants: [Grant] = []
  var migrated: [String] = []
  let store: JSONStore
  /// Grants added or removed
  var onChange: ([Grant]) -> Void = { _ in }

  init(storage: Storage) {
    store = storage.store("grants.json")
    store.encode = { [unowned self] in
      ["schema": 1, "grants": .array(grants.map(\.json)), "migrated": JSON(migrated)]
    }
  }
  func load() {
    store.load { data in
      guard data["schema"]?.int == 1, let grants = data["grants"]?.array else { throw ChannelFailure("unsupported grants file") }
      self.grants = try grants.map {
        Grant(id: $0["id"]?.string ?? UUID().uuidString.lowercased(), subject: try GrantSubject($0["subject"]),
          object: try GrantObject($0["object"]), by: $0["by"]?.string ?? "", at: $0["at"]?.string ?? "")
      }
      migrated = data["migrated"]?.strings ?? []
    }
  }
  /// Adds a grant, or returns the same one if it exists
  @discardableResult
  func add(_ subject: GrantSubject, _ object: GrantObject, by: String) -> Grant {
    if let existing = grants.first(where: { $0.subject == subject && $0.object == object }) { return existing }
    let grant = Grant(id: newId(), subject: subject, object: object, by: by, at: isoNow())
    grants.append(grant)
    changed([grant])
    return grant
  }
  func remove(id: String?) -> Grant? {
    guard let index = grants.firstIndex(where: { $0.id == id }) else { return nil }
    let grant = grants.remove(at: index)
    changed([grant])
    return grant
  }
  @discardableResult
  func removeAll(where match: (Grant) -> Bool) -> Int {
    let removed = grants.filter(match)
    guard !removed.isEmpty else { return 0 }
    grants.removeAll(where: match)
    changed(removed)
    return removed.count
  }
  /// Replaces the subject of matching grants, keeping their ids (group renames)
  func rename(_ from: GrantSubject, to: GrantSubject) {
    var renamed: [Grant] = []
    for index in grants.indices where grants[index].subject == from {
      grants[index].subject = to
      renamed.append(grants[index])
    }
    if !renamed.isEmpty { changed(renamed) }
  }
  func allowsPath(_ caller: Caller, _ path: String) -> Bool {
    grants.contains { grant in
      switch grant.object {
      case .path(let granted): granted == path && grant.subject.matches(caller)
      case .prefix(let prefix): path.hasPrefix(prefix) && grant.subject.matches(caller)
      case .share: false
      }
    }
  }
  /// Paths (not prefixes) granted to exactly this subject, for the old call and group list APIs
  func paths(_ subject: GrantSubject) -> [String] {
    var result: [String] = []
    for grant in grants where grant.subject == subject {
      if case .path(let path) = grant.object, !result.contains(path) { result.append(path) }
    }
    return result
  }
  func allowsShare(_ caller: Caller, _ share: String) -> Bool {
    grants.contains { $0.object == .share(share) && $0.subject.matches(caller) }
  }
  private func changed(_ grants: [Grant]) {
    store.save()
    onChange(grants)
  }
}

// MARK: - Groups and members

/// An ordered map of string sets, stored as `{ key: [values] }`
struct OrderedSets {
  private(set) var keys: [String] = []
  private var sets: [String: [String]] = [:]

  init() {}
  init(_ json: JSON?) {
    guard let object = json?.object else { return }
    for (key, values) in object {
      for value in values.strings ?? [] { insert(value, into: key) }
    }
  }
  var json: JSON { .object(JSONObject(keys.map { ($0, JSON(sets[$0] ?? [])) })) }
  var isEmpty: Bool { keys.isEmpty }
  var count: Int { sets.values.reduce(0) { $0 + $1.count } }
  func values(_ key: String) -> [String] { sets[key] ?? [] }
  func contains(_ value: String, in key: String) -> Bool { sets[key]?.contains(value) ?? false }
  @discardableResult
  mutating func insert(_ value: String, into key: String) -> Bool {
    if sets[key] == nil {
      keys.append(key)
      sets[key] = []
    }
    guard !sets[key]!.contains(value) else { return false }
    sets[key]!.append(value)
    return true
  }
  @discardableResult
  mutating func remove(_ value: String, from key: String) -> Bool {
    guard let index = sets[key]?.firstIndex(of: value) else { return false }
    sets[key]!.remove(at: index)
    if sets[key]!.isEmpty { removeKey(key) }
    return true
  }
  @discardableResult
  mutating func removeKey(_ key: String) -> [String]? {
    guard let values = sets.removeValue(forKey: key) else { return nil }
    keys.removeAll { $0 == key }
    return values
  }
  mutating func renameKey(_ from: String, to: String) {
    guard let values = removeKey(from) else { return }
    for value in values { insert(value, into: to) }
  }
}

/// `group-members.json`: members of groups (`key:<SPKI>` or `device:<id>`), the built-in `owners` group included
final class Members {
  private(set) var groups = OrderedSets()
  let store: JSONStore
  var onChange: (String) -> Void = { _ in }

  init(storage: Storage) {
    store = storage.store("group-members.json")
    store.encode = { [unowned self] in ["schema": 1, "groups": groups.json] }
  }
  func load() {
    store.load { data in
      guard data["schema"]?.int == 1 else { throw ChannelFailure("unsupported group members file") }
      groups = OrderedSets(data["groups"])
    }
  }
  func has(_ member: String, in group: String) -> Bool { groups.contains(member, in: group) }
  func members(_ group: String) -> [String] { groups.values(group) }
  func groupsOf(_ principal: Principal) -> [String] {
    let key = principal.key.map(keyMember)
    let device = principal.device.map(deviceMember)
    return groups.keys.filter { group in
      (key.map { groups.contains($0, in: group) } ?? false) || (device.map { groups.contains($0, in: group) } ?? false)
    }
  }
  func add(_ member: String, to group: String) {
    if groups.insert(member, into: group) { changed(group) }
  }
  func remove(_ member: String, from group: String) {
    if groups.remove(member, from: group) { changed(group) }
  }
  /// Takes the member out of every group
  func removeEverywhere(_ member: String) {
    for group in groups.keys where groups.remove(member, from: group) { changed(group) }
  }
  func removeGroup(_ group: String) {
    guard group != ownersGroup, groups.removeKey(group) != nil else { return }
    changed(group)
  }
  func renameGroup(_ from: String, to: String) {
    guard from != ownersGroup, !groups.values(from).isEmpty else { return }
    groups.renameKey(from, to: to)
    changed(to)
  }
  private func changed(_ group: String) {
    store.save()
    onChange(group)
  }
}

/// `groups.json`: which groups exist and whether they are people
final class Groups {
  private(set) var names: [String] = []
  private var people = Set<String>()
  let store: JSONStore
  var onChange: () -> Void = {}

  init(storage: Storage) {
    store = storage.store("groups.json")
    store.encode = { [unowned self] in
      ["schema": 1, "groups": .object(JSONObject(names.map { ($0, people.contains($0) ? ["person": true] : [:]) }))]
    }
  }
  func load() {
    store.load { data in
      guard let object = data.object else { throw ChannelFailure("not an object") }
      if object["schema"] == nil {
        // The old format, group → paths: only the names are kept here
        names = object.keys
      } else {
        guard object["schema"]?.int == 1 else { throw ChannelFailure("unsupported groups schema") }
        for (name, info) in data["groups"]?.object ?? [:] {
          names.append(name)
          if info["person"] == .bool(true) { people.insert(name) }
        }
      }
    }
  }
  func has(_ group: String) -> Bool { group == ownersGroup || names.contains(group) }
  func isPerson(_ group: String) -> Bool { people.contains(group) }
  /// `hub/group/create`: a name, or `{ name, person? }`. Returns the group id (its name).
  func create(_ value: JSON?) throws -> String {
    let name = value?.string ?? value?["name"]?.string
    guard let name, !name.trimmingCharacters(in: .whitespaces).isEmpty else { throw ChannelFailure("invalid group") }
    if name == ownersGroup || names.contains(name) { return name }
    names.append(name)
    if value?["person"] == .bool(true) { people.insert(name) }
    changed()
    return name
  }
  func remove(_ group: String) -> Bool {
    guard let index = names.firstIndex(of: group) else { return false }
    names.remove(at: index)
    people.remove(group)
    changed()
    return true
  }
  func rename(_ group: String, to name: String) -> Bool {
    guard let index = names.firstIndex(of: group) else { return false }
    names[index] = name
    if people.remove(group) != nil { people.insert(name) }
    changed()
    return true
  }
  /// Remembers a group that only appeared as a grant or member
  func ensure(_ group: String) {
    guard !has(group) else { return }
    names.append(group)
    changed()
  }
  private func changed() {
    store.save()
    onChange()
  }
}

/// `paths.json`: display names of restricted paths. In `default-allow`, a path with a name needs a grant.
final class PathNames {
  private(set) var names = JSONObject()
  let store: JSONStore
  var onChange: () -> Void = {}

  init(storage: Storage) {
    store = storage.store("paths.json")
    store.encode = { [unowned self] in .object(names) }
    setHubApi()
  }
  func load() {
    store.load { data in
      guard let object = data.object else { throw ChannelFailure("not an object") }
      names = object
      setHubApi()
    }
  }
  private func setHubApi() {
    for (path, name) in hubApiNames { names[path] = .string(name) }
  }
  func contains(_ path: String) -> Bool { names.contains(path) }
  /// A built-in API's name, not stored
  func register(_ path: String, name: String) {
    names[path] = .string(name)
  }
  func add(_ path: String, name: String) {
    guard names[path] != .string(name) else { return }
    names[path] = .string(name)
    store.save()
    onChange()
  }
}

/// `services.json`: which keys may host which paths. Requests waiting for approval stay in memory.
final class HostApprovals {
  private(set) var allowed = OrderedSets()
  private(set) var pending = OrderedSets()
  let store: JSONStore
  var onPendingChange: () -> Void = {}

  init(storage: Storage) {
    store = storage.store("services.json")
    store.encode = { [unowned self] in ["allowed": allowed.json] }
  }
  func load() {
    store.load { data in allowed = OrderedSets(data["allowed"]) }
  }
  func allows(_ key: String, _ path: String) -> Bool { allowed.contains(path, in: key) }
  func ask(_ key: String, _ path: String) {
    if pending.insert(path, into: key) { onPendingChange() }
  }
  func allow(_ key: String, _ paths: [String]) {
    guard !paths.isEmpty else { return }
    for path in paths {
      pending.remove(path, from: key)
      allowed.insert(path, into: key)
    }
    store.save()
    onPendingChange()
  }
  func revoke(_ key: String, _ paths: [String]) {
    guard !paths.isEmpty else { return }
    for path in paths {
      pending.insert(path, into: key)
      allowed.remove(path, from: key)
    }
    store.save()
    onPendingChange()
  }
  func forget(_ key: String) {
    revoke(key, allowed.values(key))
    if pending.removeKey(key) != nil { onPendingChange() }
  }
}

/// `whitelist.json`: lockdown mode, only listed keys (and owners) may connect
final class Whitelist {
  private(set) var enabled = false
  private(set) var users: [String] = []
  let store: JSONStore
  var onChange: () -> Void = {}

  init(storage: Storage) {
    store = storage.store("whitelist.json")
    store.encode = { [unowned self] in ["enabled": .bool(enabled), "whitelist": JSON(users)] }
  }
  func load() {
    store.load { data in
      guard data.object != nil else { throw ChannelFailure("not an object") }
      enabled = data["enabled"]?.bool ?? false
      users = data["whitelist"]?.strings ?? []
    }
  }
  /// Enabled, or its file is corrupt and only owners get in
  var enforced: Bool { enabled || store.corrupt }
  var json: JSON { ["enabled": .bool(enabled), "users": JSON(users)] }
  func contains(_ key: String) -> Bool { !store.corrupt && users.contains(key) }
  func add(_ key: String) {
    guard !users.contains(key) else { return }
    users.append(key)
    changed()
  }
  func remove(_ key: String) {
    guard let index = users.firstIndex(of: key) else { return }
    users.remove(at: index)
    changed()
  }
  func setEnabled(_ value: Bool?) {
    guard let value, value != enabled else { return }
    enabled = value
    changed()
  }
  private func changed() {
    store.save()
    onChange()
  }
}

/// `hub.json`: security mode and hub settings. Unknown fields are kept.
final class HubSettings {
  private(set) var data = JSONObject()
  private(set) var mode: SecurityMode = .defaultDeny
  private(set) var requireV1 = false
  let store: JSONStore

  init(storage: Storage) {
    store = storage.store("hub.json")
    store.encode = { [unowned self] in .object(data) }
  }
  /// A first start (no `hub.json` and no hub key file) gets `default-deny`; a hub that ran before without a stored
  /// mode gets `default-allow`; a corrupt `hub.json` gets `default-deny`. The mode is written at once.
  func load(hubKeyExisted: Bool) {
    let existed = store.exists
    var storedMode = false
    store.load { json in
      guard let object = json.object else { throw ChannelFailure("not an object") }
      data = object
      storedMode = json["security"]?["mode"]?.string != nil
      mode = json["security"]?["mode"]?.string == SecurityMode.defaultDeny.rawValue ? .defaultDeny : .defaultAllow
      requireV1 = json["security"]?["requireV1"] == .bool(true)
    }
    if store.corrupt {
      data = [:]
      mode = .defaultDeny
    } else if !existed {
      mode = hubKeyExisted ? .defaultAllow : .defaultDeny
    }
    if data["merge"] == nil { data["merge"] = [] }
    if data["proxies"] == nil { data["proxies"] = [] }
    if data["api"] == nil { data["api"] = [:] }
    if data["pendingLimit"] == nil { data["pendingLimit"] = 0 }
    if data["mergeKeys"] == nil { data["mergeKeys"] = [:] }
    writeSecurity()
    if !existed || store.corrupt || !storedMode { store.writeNow() }
  }
  private func writeSecurity() {
    data["security"] = ["mode": .string(mode.rawValue), "requireV1": .bool(requireV1)]
  }
  func setSecurity(mode: SecurityMode?, requireV1: Bool?) {
    let changed = (mode != nil && mode != self.mode) || (requireV1 != nil && requireV1 != self.requireV1)
    if let mode { self.mode = mode }
    if let requireV1 { self.requireV1 = requireV1 }
    writeSecurity()
    if changed { store.save() }
  }
  var pendingLimit: Int { data["pendingLimit"]?.int ?? 0 }
  func setPendingLimit(_ limit: Int) {
    guard limit != pendingLimit else { return }
    data["pendingLimit"] = .int(limit)
    store.save()
  }
  func balancer(_ path: String) -> String? { data["api"]?[path]?["loadBalancer"]?.string }
  func setBalancer(_ path: String, _ name: String) {
    guard balancer(path) != name else { return }
    var api = data["api"]?.object ?? [:]
    var settings = api[path]?.object ?? [:]
    settings["loadBalancer"] = .string(name)
    api[path] = .object(settings)
    data["api"] = .object(api)
    store.save()
  }
}

// MARK: - Security

final class Security {
  let grants: GrantStore
  let members: Members
  let groups: Groups
  let names: PathNames
  let host: HostApprovals
  let whitelist: Whitelist
  let settings: HubSettings
  /// Per-key call requests waiting for an owner, in memory (`hub/call/pending`)
  private(set) var callPending = OrderedSets()
  /// The launcher key, which may host `launcher/*` and enrols its device at once
  var launcher: String?
  let hubKey: String
  /// Device names for `caller.device`
  var deviceName: (String) -> String? = { _ in nil }
  /// A store that grants or tombstones failed to load: only owners may call service paths until an owner sets the mode
  private(set) var lockdown = false

  init(storage: Storage, hubKey: String) {
    self.hubKey = hubKey
    grants = GrantStore(storage: storage)
    members = Members(storage: storage)
    groups = Groups(storage: storage)
    names = PathNames(storage: storage)
    host = HostApprovals(storage: storage)
    whitelist = Whitelist(storage: storage)
    settings = HubSettings(storage: storage)
  }

  func load(hubKeyExisted: Bool) {
    settings.load(hubKeyExisted: hubKeyExisted)
    grants.load()
    members.load()
    groups.load()
    names.load()
    host.load()
    whitelist.load()
    // An empty path list or whitelist opens the hub and an empty owners group keeps owners out, so a corrupt one
    // locks the hub down instead
    if [settings.store, names.store, whitelist.store, members.store, grants.store].contains(where: \.corrupt) { lockDown() }
  }

  /// Local mode (protocol.md section 12): `default-allow` and the launcher key is an owner, neither stored
  var local = false
  var mode: SecurityMode { local ? .defaultAllow : settings.mode }
  var requireV1: Bool { settings.requireV1 }
  /// `default-deny` while locked down
  var effectiveMode: SecurityMode { lockdown ? .defaultDeny : mode }
  /// The launcher key in local mode
  private func isLocalOwner(_ key: String?) -> Bool {
    local && key != nil && key == launcher
  }

  /// Only owners may call service paths, and the hub stays `default-deny` after a restart
  func lockDown() {
    lockdown = true
    settings.setSecurity(mode: .defaultDeny, requireV1: nil)
  }
  /// `hub/security/mode/set`. An owner setting it ends a lockdown.
  func setMode(_ body: JSON?) throws {
    var mode: SecurityMode?
    if let value = body?["mode"], !value.isNull {
      guard let parsed = value.string.flatMap(SecurityMode.init(rawValue:)) else { throw ChannelFailure("invalid mode") }
      mode = parsed
    }
    var requireV1: Bool?
    if let value = body?["requireV1"], !value.isNull {
      guard let parsed = value.bool else { throw ChannelFailure("invalid requireV1") }
      requireV1 = parsed
    }
    settings.setSecurity(mode: mode, requireV1: requireV1)
    lockdown = false
  }

  // MARK: Identity

  /// Adds a service or device SPKI to `owners`, as `key:` and as the device it would be
  func addOwner(_ key: String) {
    members.add(keyMember(key), to: ownersGroup)
    members.add(deviceMember(HubCrypto.deviceId(spki: key)), to: ownersGroup)
  }
  /// Stored owners, which local mode's launcher isn't
  var hasOwners: Bool { !members.members(ownersGroup).isEmpty }

  func caller(_ principal: Principal) -> Caller {
    let groups = self.groups(principal)
    let device = principal.device.map { (id: $0, name: deviceName($0) ?? $0) }
    return Caller(key: principal.key, device: device, groups: groups, owner: groups.contains(ownersGroup))
  }
  /// Every group the key or its device belongs to, `owners` first
  func groups(_ principal: Principal) -> [String] {
    var groups = members.groupsOf(principal)
    if isLocalOwner(principal.key), !groups.contains(ownersGroup) { groups.append(ownersGroup) }
    return groups.contains(ownersGroup) ? [ownersGroup] + groups.filter { $0 != ownersGroup } : groups
  }
  func isOwner(_ principal: Principal) -> Bool {
    isLocalOwner(principal.key) || (principal.key.map { members.has(keyMember($0), in: ownersGroup) } ?? false)
      || (principal.device.map { members.has(deviceMember($0), in: ownersGroup) } ?? false)
  }

  // MARK: Checks

  /// A call to a service path: owners always; then grants; then in `default-deny` only paths the providing service
  /// marked public, in `default-allow` every path without a restricting name
  func allowsCall(_ caller: Caller, _ path: String, isPublic: Bool) -> Bool {
    if caller.owner { return true }
    if lockdown { return false }
    if grants.allowsPath(caller, path) { return true }
    if mode == .defaultDeny { return isPublic }
    return !names.contains(path)
  }

  /// Access check for a built-in path
  func checkBuiltin(_ caller: Caller, _ path: String) throws {
    switch builtinAccess(path) {
    case nil, .open, .own, .reporter:
      // Reporter handlers check that the caller is its device's reporter
      return
    case .auth:
      if caller.key == nil { throw ChannelFailure.unauthorized }
    case .grant:
      // Approved devices are members and read the directory of their hub; others need a grant
      if caller.owner || (!lockdown && (caller.device != nil || grants.allowsPath(caller, path))) { return }
      throw ChannelFailure.forbidden
    case .owner:
      if !caller.owner { throw ChannelFailure.forbidden }
    }
  }

  func allowsBuiltin(_ caller: Caller, _ path: String) -> Bool {
    (try? checkBuiltin(caller, path)) != nil
  }

  /// Whether the connection may provide the path. Asks the owners when it may not.
  func allowsHost(_ principal: Principal, _ path: String) -> Bool {
    guard let key = principal.key else { return false }
    if path == "hub" || path.hasPrefix("hub/") { return false }
    if let launcher, key == launcher, path.hasPrefix("launcher/") { return true }
    if isOwner(principal) { return true }
    if host.allows(key, path) { return true }
    host.ask(key, path)
    return false
  }

  /// Checks an `auth` header. Returns the key, nil for an anonymous connection; throws to refuse the connection.
  func verifyToken(_ token: String?, version: String?, now: Int = Int(Date().timeIntervalSince1970)) throws -> String? {
    let version = version ?? "0"
    guard version == "0" || version == "1" else { throw ChannelFailure("unsupported version") }
    guard let token, !token.isEmpty else {
      if whitelist.enforced { throw ChannelFailure("hub is not available") }
      return nil
    }
    if version == "0", requireV1 { throw ChannelFailure("unsupported version") }
    let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 4, parts[0] == "key" else { throw ChannelFailure("invalid key") }
    let key = parts[1], signature = parts[2], time = parts[3]
    if whitelist.enforced, !isOwner(Principal(key: key)), !whitelist.contains(key) { throw ChannelFailure("hub is not available") }
    guard (1...12).contains(time.count), time.allSatisfy(\.isASCII), time.allSatisfy(\.isNumber), let expiry = Int(time) else {
      throw ChannelFailure("invalid key")
    }
    if expiry + authClockSkew <= now { throw ChannelFailure("authorization expired") }
    if expiry > now + authMaxLifetime + authClockSkew { throw ChannelFailure("authorization expires too late") }
    let signed = version == "1" ? "hub1:\(hubKey):\(time)" : time
    guard HubCrypto.publicKey(spki: key) != nil else { throw ChannelFailure("invalid key") }
    guard HubCrypto.verify(signature: signature, message: signed, spki: key) else { throw ChannelFailure("invalid signature") }
    return key
  }

  // MARK: Changes

  /// `hub/grant/add`
  func addGrant(_ body: JSON?, by caller: Caller) throws -> Grant {
    let subject = try GrantSubject(body?["subject"])
    let object = try GrantObject(body?["object"])
    return grants.add(subject, object, by: caller.key ?? "owner")
  }
  /// Removes grants naming a removed device and drops it from every group
  func removeDevice(_ id: String) {
    grants.removeAll { $0.subject == .device(id) }
    members.removeEverywhere(deviceMember(id))
  }
  /// Drops what a revoked key was granted: its grants, hosting approvals and group memberships
  func revokeKey(_ key: String) {
    grants.removeAll { $0.subject == .key(key) }
    if callPending.removeKey(key) != nil {}
    host.forget(key)
    members.removeEverywhere(keyMember(key))
  }

  // MARK: Old per-key call lists, now key grants

  func askCall(_ key: String, _ path: String) {
    callPending.insert(path, into: key)
  }
  func allowCalls(_ key: String, _ paths: [String], by: String) {
    for path in paths {
      callPending.remove(path, from: key)
      grants.add(.key(key), .path(path), by: by)
    }
  }
  func revokeCalls(_ key: String, _ paths: [String]) {
    let revoked = Set(paths)
    for path in paths { callPending.insert(path, into: key) }
    grants.removeAll { grant in
      guard grant.subject == .key(key), case .path(let path) = grant.object else { return false }
      return revoked.contains(path)
    }
  }

  // MARK: Group listings

  /// `hub/group/list`: group → granted paths
  var groupList: JSON {
    .object(JSONObject(groups.names.map { ($0, JSON(grants.paths(.group($0)))) }))
  }
  /// `hub/group/users`: group → members, keys as plain SPKIs
  var groupUsers: JSON {
    .object(JSONObject(members.groups.keys.map { group in
      (group, JSON(members.members(group).map { $0.hasPrefix("key:") ? String($0.dropFirst(4)) : $0 }))
    }))
  }
  /// `hub/groups`: every group with its kind, members and paths, `owners` first
  var groupInfo: JSON {
    let ids = [ownersGroup] + groups.names.filter { $0 != ownersGroup }
    return .array(ids.map { id in
      ["id": .string(id), "person": .bool(groups.isPerson(id)), "members": JSON(members.members(id)),
       "paths": JSON(grants.paths(.group(id)))]
    })
  }
  /// The first group of the key other than owners, for connection lists
  func userGroup(_ key: String?) -> String? {
    guard let key else { return nil }
    return members.groupsOf(Principal(key: key)).first { $0 != ownersGroup }
  }
}

/// Longest auth token lifetime the hub accepts, in seconds
let authMaxLifetime = 300
/// Tolerated clock difference between signer and hub, in seconds
let authClockSkew = 30

func isoNow() -> String { isoDate(Date()) }
func isoDate(_ date: Date) -> String {
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  return formatter.string(from: date)
}
/// A time-ordered unique id, like `randomUUIDv7`
func newId() -> String {
  var bytes = HubCrypto.randomBytes(16)
  let milliseconds = UInt64(Date().timeIntervalSince1970 * 1000)
  for index in 0..<6 { bytes[index] = UInt8(milliseconds >> UInt64(40 - index * 8) & 0xFF) }
  bytes[6] = bytes[6] & 0x0F | 0x70
  bytes[8] = bytes[8] & 0x3F | 0x80
  let hex = HubCrypto.hex(bytes)
  let characters = Array(hex)
  return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(characters[$0]) }.joined(separator: "-")
}
