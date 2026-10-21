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
  init(connection: HubConnection, enabled: Bool) {
    self.connection = connection
    self.enabled = enabled
  }
  var load: Int { running.count }
  var isLimited: Bool { limit > 0 && load >= limit }
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
      return providers.first { $0.load == 0 && !$0.isLimited }
    case .available:
      let start = index + 1 >= providers.count ? 0 : index + 1
      for offset in 0..<providers.count {
        let candidate = (start + offset) % providers.count
        if providers[candidate].load == 0 {
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
  let path: String
  var requests = 0
  private(set) var providers: [Provider] = []
  private(set) var disabled: [Provider] = []
  /// Requests waiting for a provider
  private var pending: [(Provider?) -> Void] = []
  /// Connections whose header marked the path `public`
  private var publicConnections = Set<ObjectIdentifier>()
  private(set) var balancer = LoadBalancer(.counter)
  private var limited = false
  /// Has providers, so the path is in the hub's API
  private(set) var isEnabled = false

  init(path: String) {
    self.path = path
  }

  /// Adds a provider. Returns true when the path became available.
  @discardableResult
  func add(_ provider: Provider) -> Bool {
    if provider.enabled {
      guard !providers.contains(where: { $0.connection === provider.connection }) else { return false }
      providers.append(provider)
      let enabled = enable()
      if !pending.isEmpty, let next = balancer.next(providers) { pending.removeFirst()(next) }
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
    let revoked = providers.filter { $0.connection.key == key }
    guard !revoked.isEmpty else { return (0, false) }
    for provider in revoked {
      if let index = providers.firstIndex(where: { $0 === provider }) {
        providers.remove(at: index)
        balancer.removed(at: index)
      }
      provider.enabled = false
      disabled.append(provider)
      abort(provider)
    }
    return (revoked.count, disable())
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
    for waiter in pending { waiter(nil) }
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
    providers.contains { publicConnections.contains(ObjectIdentifier($0.connection)) }
  }

  func setLimit(_ connection: HubConnection, _ limit: Int) {
    if limit > 0, !limited {
      limited = true
      if !balancer.kind.allowsLimit { balancer = LoadBalancer(.counter) }
    }
    (providers + disabled).first { $0.connection === connection }?.limit = limit
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

  /// The next provider, nil when requests are waiting or every provider is busy
  func next() -> Provider? {
    guard pending.isEmpty else { return nil }
    return balancer.next(providers)
  }

  /// Waits for a provider. With a positive `limit`, the oldest waiting requests are dropped beyond it.
  func wait(limit: Int, _ waiter: @escaping (Provider?) -> Void) {
    if limit > 0 {
      let drop = pending.count + 1 - limit
      if drop > 0 {
        let dropped = pending.prefix(drop)
        pending.removeFirst(drop)
        for waiter in dropped { waiter(nil) }
      }
    }
    pending.append(waiter)
  }

  /// A request finished: the provider goes to the next waiting request
  func completed(_ provider: Provider) {
    guard !pending.isEmpty, provider.enabled, providers.contains(where: { $0 === provider }) else { return }
    pending.removeFirst()(provider)
  }

  var status: JSON {
    ["name": .string(path), "services": .int(providers.count), "disabled": .int(disabled.count), "requests": .int(requests),
     "balancer": .string(balancer.kind.rawValue), "pending": .int(pending.count),
     "running": .int(providers.reduce(0) { $0 + $1.load })]
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
