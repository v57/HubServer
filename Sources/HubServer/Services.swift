import ChannelServer
import Foundation

/// One connection to the hub
final class HubConnection {
  let id: String
  /// Set once the WebSocket is open. Weak: the peer holds the connection as its state.
  weak var peer: ChannelPeer?
  let key: String?
  var name: String?
  var icon: JSON?
  /// Paths it provides
  var services = Set<String>()
  var apps = Set<String>()
  let ip: String?
  /// Device id, when the connection has a certificate from an approved device
  var device: String?
  /// Instance name from the certificate of a device connection
  var instance: String?
  /// A valid certificate, also from a pending device
  var certificate: Certificate?
  var isOpen = false
  /// Its paths take no new calls (`hub/service/update { draining: true }`); running calls go on
  var draining = false

  init(key: String?, ip: String?) {
    self.id = newId()
    self.key = key
    self.ip = ip
  }
  var principal: Principal { Principal(key: key, device: device) }
}

/// A connection providing one path
final class Provider {
  unowned let connection: HubConnection
  var enabled: Bool
  /// Requests and streams in flight, with what aborts each when the provider goes away
  var running: [Int: () -> Void] = [:]
  var limit = 0
  /// Handed to waiting calls that haven't started yet; counts against `limit`
  var reserved = 0
  /// Takes no new calls, see `ServiceGroup.setDraining`
  var draining: Bool
  init(connection: HubConnection, enabled: Bool) {
    self.connection = connection
    self.enabled = enabled
    self.draining = connection.draining
  }
  var load: Int { running.count }
  var isLimited: Bool { limit > 0 && load + reserved >= limit }
  /// Nothing running or about to
  var isIdle: Bool { load == 0 && reserved == 0 }
}

/// Picks the provider of the next request
final class LoadBalancer {
  enum Kind: String {
    case random, counter, first, available
    var allowsLimit: Bool { self != .random }
  }
  let kind: Kind
  private var index = 0
  init(_ kind: Kind) {
    self.kind = kind
  }

  func next(_ providers: [Provider]) -> Provider? {
    guard !providers.isEmpty else { return nil }
    switch kind {
    case .random:
      return providers.randomElement()
    case .counter:
      for _ in 0..<providers.count {
        index += 1
        if index >= providers.count { index = 0 }
        if !providers[index].isLimited { return providers[index] }
      }
      return nil
    case .first:
      return providers.first { $0.isIdle && !$0.isLimited }
    case .available:
      let start = index + 1 >= providers.count ? 0 : index + 1
      for offset in 0..<providers.count {
        let candidate = (start + offset) % providers.count
        if providers[candidate].isIdle {
          index = candidate
          return providers[candidate]
        }
      }
      return nil
    }
  }
  /// Keeps the counter on the same provider when an earlier one leaves
  func removed(at position: Int) {
    if position < index { index -= 1 }
  }
}

/// Everyone providing one path
final class ServiceGroup {
  /// How long a call waits for a provider before failing with `api not available`
  static var waitTimeout: TimeInterval = 30
  static let notAvailable = ChannelFailure("api not available", code: "unavailable")

  /// A call waiting for a provider
  private final class Waiter {
    let id: Int
    let resolve: (Provider) -> Void
    let fail: (ChannelFailure) -> Void
    var timer: DispatchWorkItem?
    init(id: Int, resolve: @escaping (Provider) -> Void, fail: @escaping (ChannelFailure) -> Void) {
      self.id = id
      self.resolve = resolve
      self.fail = fail
    }
  }

  let path: String
  private let queue: DispatchQueue
  var requests = 0
  private(set) var providers: [Provider] = []
  private(set) var disabled: [Provider] = []
  /// Enabled providers that take no new calls; their running calls go on
  private(set) var draining: [Provider] = []
  /// Calls waiting for a provider, oldest first
  private var pending: [Waiter] = []
  private var nextWaiter = 0
  /// Connections whose header marked the path `public`
  private var publicConnections = Set<ObjectIdentifier>()
  private(set) var balancer = LoadBalancer(.counter)
  private var limited = false
  /// Has providers, so the path is in the hub's API
  private(set) var isEnabled = false

  init(path: String, queue: DispatchQueue) {
    self.path = path
    self.queue = queue
  }

  /// Adds a provider. Returns true when the path became available.
  @discardableResult
  func add(_ provider: Provider) -> Bool {
    if provider.enabled, provider.draining {
      if !draining.contains(where: { $0.connection === provider.connection }) { draining.append(provider) }
      return false
    } else if provider.enabled {
      guard !providers.contains(where: { $0.connection === provider.connection }) else { return false }
      providers.append(provider)
      let enabled = enable()
      drain()
      return enabled
    } else {
      if !disabled.contains(where: { $0.connection === provider.connection }) { disabled.append(provider) }
      return false
    }
  }

  /// Removes the connection's provider, aborting its requests. Returns true when the path became unavailable.
  @discardableResult
  func remove(_ connection: HubConnection) -> Bool {
    publicConnections.remove(ObjectIdentifier(connection))
    disabled.removeAll { $0.connection === connection }
    if let index = draining.firstIndex(where: { $0.connection === connection }) {
      abort(draining.remove(at: index))
      return false
    }
    guard let index = providers.firstIndex(where: { $0.connection === connection }) else { return false }
    let provider = providers.remove(at: index)
    balancer.removed(at: index)
    abort(provider)
    return disable()
  }

  /// An owner allowed the key to host the path: its waiting connections start providing. Returns how many.
  func allowKey(_ key: String) -> (count: Int, enabled: Bool) {
    let allowed = disabled.filter { $0.connection.key == key }
    guard !allowed.isEmpty else { return (0, false) }
    disabled.removeAll { $0.connection.key == key }
    var enabled = false
    for provider in allowed {
      provider.enabled = true
      enabled = add(provider) || enabled
    }
    return (allowed.count, enabled)
  }

  /// An owner revoked the key's hosting: its providers stop, their requests are aborted
  func revokeKey(_ key: String) -> (count: Int, disabled: Bool) {
    let drained = draining.filter { $0.connection.key == key }
    draining.removeAll { $0.connection.key == key }
    for provider in drained {
      provider.enabled = false
      disabled.append(provider)
      abort(provider)
    }
    let revoked = providers.filter { $0.connection.key == key }
    guard !revoked.isEmpty else { return (drained.count, false) }
    for provider in revoked {
      if let index = providers.firstIndex(where: { $0 === provider }) {
        providers.remove(at: index)
        balancer.removed(at: index)
      }
      provider.enabled = false
      disabled.append(provider)
      abort(provider)
    }
    return (revoked.count + drained.count, disable())
  }

  /// Moves the connection's provider out of or back into load balancing, keeping its running calls. A path whose
  /// last provider drains becomes unavailable (`isEnabled` false) and calls to it keep waiting for another provider.
  func setDraining(_ connection: HubConnection, _ value: Bool) {
    if let provider = disabled.first(where: { $0.connection === connection }) {
      provider.draining = value
      return
    }
    if value {
      guard let index = providers.firstIndex(where: { $0.connection === connection }) else { return }
      let provider = providers.remove(at: index)
      balancer.removed(at: index)
      provider.draining = true
      draining.append(provider)
      if isEnabled, providers.isEmpty { isEnabled = false }
    } else {
      guard let index = draining.firstIndex(where: { $0.connection === connection }) else { return }
      let provider = draining.remove(at: index)
      provider.draining = false
      _ = add(provider)
    }
  }

  private func abort(_ provider: Provider) {
    let running = provider.running.values
    provider.running = [:]
    for abort in running { abort() }
  }

  private func enable() -> Bool {
    guard !isEnabled, !providers.isEmpty else { return false }
    isEnabled = true
    return true
  }

  private func disable() -> Bool {
    guard isEnabled, providers.isEmpty else { return false }
    isEnabled = false
    let pending = self.pending
    self.pending = []
    for waiter in pending {
      waiter.timer?.cancel()
      waiter.fail(.apiNotFound)
    }
    return true
  }

  func setPublic(_ connection: HubConnection, _ isPublic: Bool) {
    if isPublic {
      publicConnections.insert(ObjectIdentifier(connection))
    } else {
      publicConnections.remove(ObjectIdentifier(connection))
    }
  }
  /// Callable by anyone in `default-deny`: an enabled provider marked the path public
  var isPublic: Bool {
    (providers + draining).contains { publicConnections.contains(ObjectIdentifier($0.connection)) }
  }

  func setLimit(_ connection: HubConnection, _ limit: Int) {
    if limit > 0, !limited {
      limited = true
      if !balancer.kind.allowsLimit { balancer = LoadBalancer(.counter) }
    }
    (providers + disabled + draining).first { $0.connection === connection }?.limit = limit
    drain()
  }

  func setBalancer(_ kind: LoadBalancer.Kind) {
    guard kind != balancer.kind, !limited || kind.allowsLimit else { return }
    balancer = LoadBalancer(kind)
  }

  /// The provider `context.service` (connection id or key) or `context.device` (device id) asks for. A device with
  /// no provider of the path fails with `api not found`; an unknown service falls back to load balancing.
  func select(_ context: JSON) throws -> Provider? {
    let device = context["device"]?.string
    if let service = context["service"]?.string,
      let selected = providers.first(where: { ($0.connection.key == service || $0.connection.id == service) && (device == nil || $0.connection.device == device) })
    {
      return selected
    }
    guard let device else { return nil }
    let onDevice = providers.filter { $0.connection.device == device }
    guard let first = onDevice.first else { throw ChannelFailure.apiNotFound }
    return onDevice.reduce(first) { $1.load < $0.load ? $1 : $0 }
  }

  /// A provider for a new call. Older waiting calls are served first; a provider left over goes to this one.
  func next() -> Provider? {
    drain()
    guard pending.isEmpty else { return nil }
    return balancer.next(providers)
  }

  /// Waits for a provider; `next()` had none. Fails with `api not available` after `waitTimeout`, or when a positive
  /// `limit` of newer waiting calls pushes it out. The caller passes the provider it gets to `claimed`. Returns the
  /// waiter's id, for `cancelWait`.
  @discardableResult
  func wait(limit: Int, resolve: @escaping (Provider) -> Void, fail: @escaping (ChannelFailure) -> Void) -> Int {
    nextWaiter += 1
    let waiter = Waiter(id: nextWaiter, resolve: resolve, fail: fail)
    let timer = DispatchWorkItem { [weak self, weak waiter] in
      guard let self, let waiter, let index = self.pending.firstIndex(where: { $0 === waiter }) else { return }
      self.pending.remove(at: index)
      waiter.fail(ServiceGroup.notAvailable)
    }
    waiter.timer = timer
    queue.asyncAfter(deadline: .now() + ServiceGroup.waitTimeout, execute: timer)
    pending.append(waiter)
    if limit > 0, pending.count > limit {
      let evicted = pending.prefix(pending.count - limit)
      pending.removeFirst(evicted.count)
      for old in evicted {
        old.timer?.cancel()
        old.fail(ServiceGroup.notAvailable)
      }
    }
    return waiter.id
  }

  /// The waiting call was cancelled
  func cancelWait(_ id: Int) {
    guard let index = pending.firstIndex(where: { $0.id == id }) else { return }
    pending.remove(at: index).timer?.cancel()
  }

  /// Hands free providers to waiting calls, oldest first, reserving each until its call starts
  private func drain() {
    while !pending.isEmpty, let provider = balancer.next(providers) {
      let waiter = pending.removeFirst()
      waiter.timer?.cancel()
      provider.reserved += 1
      waiter.resolve(provider)
    }
  }

  /// A waiting call got `provider` and starts now
  func claimed(_ provider: Provider) {
    if provider.reserved > 0 { provider.reserved -= 1 }
  }

  /// A call ended, so its provider may take a waiting one
  func completed(_ provider: Provider) {
    drain()
  }

  var status: JSON {
    var object: JSONObject = [
      "name": .string(path), "services": .int(providers.count), "disabled": .int(disabled.count), "requests": .int(requests),
      "balancer": .string(balancer.kind.rawValue), "pending": .int(pending.count),
      "running": .int((providers + draining).reduce(0) { $0 + $1.load }),
    ]
    if !draining.isEmpty { object["draining"] = .int(draining.count) }
    return .object(object)
  }
}

/// Apps that services announce (`hub/service/update` apps), for `hub/status/badges`
final class Apps {
  private var headers: [JSONObject] = []
  private var senders: [String: Set<ObjectIdentifier>] = [:]

  var json: JSON { .array(headers.map { .object($0) }) }

  func add(_ connection: HubConnection, _ list: [JSON]) {
    for header in list {
      guard let object = header.object, let path = object["path"]?.string, !connection.apps.contains(path) else { continue }
      connection.apps.insert(path)
      if let index = headers.firstIndex(where: { $0["path"]?.string == path }) {
        headers[index]["services"] = .int((headers[index]["services"]?.int ?? 0) + 1)
      } else {
        var object = object
        object["services"] = 1
        headers.append(object)
      }
      senders[path, default: []].insert(ObjectIdentifier(connection))
    }
  }

  func remove(_ connection: HubConnection, _ paths: [String]) {
    for path in paths where connection.apps.contains(path) {
      connection.apps.remove(path)
      senders[path]?.remove(ObjectIdentifier(connection))
      if let index = headers.firstIndex(where: { $0["path"]?.string == path }) {
        headers[index]["services"] = .int(max((headers[index]["services"]?.int ?? 0) - 1, 0))
      }
    }
  }

  func removeAll(_ connection: HubConnection) {
    remove(connection, Array(connection.apps))
  }
}
