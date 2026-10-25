@_exported import ChannelServer
import Foundation

/// A Hub server that an app or a command embeds (protocol.md). Thread-safe; the hub itself runs on its own queue.
///
/// ```swift
/// var configuration = HubServer.Configuration(dataDirectory: appSupport.appendingPathComponent("Hub"))
/// configuration.devicePublicKey = deviceKey.publicKey   // the app's device key, so the hub is this device
/// let server = HubServer(configuration)
/// let port = try await server.start()
/// for await status in server.statusUpdates() { show(status.pairingCode) }
/// ```
public final class HubServer: @unchecked Sendable {
  public struct Configuration: Sendable {
    /// Where the hub keeps its key (`auth`) and stores, like hub-server's `data/`. Created if missing (0700).
    public var dataDirectory: URL
    /// 1997 on every interface by default. Local mode always listens on 127.0.0.1.
    public var listen = ListenAddress(port: 1997)
    /// Local mode (protocol.md section 12): 127.0.0.1 only, `default-allow`, the launcher key is an owner, no pairing.
    /// Nothing of it is stored.
    public var local = false
    /// Service or device SPKIs added to the owners group at start (`--owner`, `HUBOWNER`)
    public var owners: [String] = []
    /// The launcher key (`HUBLAUNCHER`): may host `launcher/*`, its device is approved at once
    public var launcherKey: String?
    /// SPKI of this machine's device key. The hub enrols it as its own, approved device with the hub key as its
    /// service. `nil`: the hub has no device.
    public var devicePublicKey: String?
    /// The hub's device name, the host name by default
    public var deviceName: String?
    /// `macos`, `ios`, `ipados`, ... (protocol.md section 3), from the OS by default
    public var platform: String? = Configuration.hostPlatform
    /// The hub's instance on its device
    public var instance = "hub-server"
    /// What runs the hub, in `hub/info`: `app` when the Hub app embeds it, so its devices know that app is the hub's
    /// Hub Network agent (the hub-net of a hub-server). `nil` for a hub-server.
    public var host: String?
    /// The hub's display name (`hub/header`) on a first start, the host name by default
    public var name: String?
    /// Makes a pairing code at start when the hub has no owners
    public var pairsAtStart = true
    /// Where the `machine` Hub Network agent of this host proves itself: its Unix socket (`/var/run/hub-net/agent.sock`
    /// on macOS, `/run/hub-net/agent.sock` on Linux, by default), or `tcp://host:port` where that socket is forwarded
    public var localAgentEndpoint: String?
    /// Where log lines go, stdout by default
    public var log: @Sendable (String) -> Void = { print($0) }

    public init(dataDirectory: URL) {
      self.dataDirectory = dataDirectory
    }

    public static var hostName: String {
      var name = ProcessInfo.processInfo.hostName
      if name.hasSuffix(".local") { name.removeLast(6) }
      return name
    }
    public static var hostPlatform: String {
      #if os(macOS) || targetEnvironment(macCatalyst)
      "macos"
      #elseif os(visionOS)
      "visionos"
      #elseif os(iOS)
      "ios"
      #elseif os(tvOS)
      "tvos"
      #elseif os(watchOS)
      "watchos"
      #elseif os(Linux)
      "linux"
      #elseif os(Windows)
      "windows"
      #elseif os(Android)
      "android"
      #else
      "other"
      #endif
    }
  }

  public enum State: Sendable, Equatable {
    case stopped
    case starting
    case running
    case failed(String)
  }

  public struct Status: Sendable, Equatable {
    public var state: State = .stopped
    /// The port it listens on while running
    public var port: UInt16?
    /// The hub's key (SPKI), which clients pin
    public var hubKey: String?
    /// The hub's display name
    public var name: String?
    public var connections = 0
    /// Who is connected, oldest first
    public var peers: [Peer] = []
    /// Owners stored in the owners group (keys and devices)
    public var owners = 0
    /// The current pairing code, when the hub has one (no owners yet, or `newPairingCode()`)
    public var pairingCode: PairingCode?
    public var local = false
    public init() {}
    init(state: State, hubKey: String? = nil, name: String? = nil, local: Bool) {
      self.state = state
      self.hubKey = hubKey
      self.name = name
      self.local = local
    }
  }

  /// A connection to the hub, for showing who is connected
  public struct Peer: Sendable, Equatable, Identifiable {
    /// Connection id
    public var id: String
    /// The name its profile gives
    public var name: String?
    /// Its device's name, when the connection is device-attached
    public var device: String?
    /// Its key (SPKI), `nil` for anonymous connections
    public var key: String?
    /// IP address it connects from
    public var address: String?
    /// Paths it provides
    public var services: Int
  }

  public let configuration: Configuration
  private let queue = DispatchQueue(label: "HubServer")
  private let lock = NSLock()
  private var hub: Hub?
  private var _status = Status()
  private var observers: [UUID: AsyncStream<Status>.Continuation] = [:]

  public init(_ configuration: Configuration) {
    self.configuration = configuration
  }

  /// A snapshot of the hub's state
  public var status: Status {
    lock.withLock { _status }
  }

  /// The current status, then every change
  public func statusUpdates() -> AsyncStream<Status> {
    AsyncStream { continuation in
      let id = UUID()
      lock.withLock {
        observers[id] = continuation
        continuation.yield(_status)
      }
      continuation.onTermination = { [weak self] _ in
        self?.lock.withLock { _ = self?.observers.removeValue(forKey: id) }
      }
    }
  }

  /// Loads the data directory and starts listening. Returns the port.
  @discardableResult
  public func start() async throws -> UInt16 {
    try await withCheckedThrowingContinuation { continuation in
      queue.async { [self] in
        guard hub == nil else { return continuation.resume(throwing: HubServerError.alreadyRunning) }
        update { $0 = Status(state: .starting, local: configuration.local) }
        let hub: Hub
        do {
          hub = try Hub(configuration: configuration, queue: queue, log: configuration.log)
        } catch {
          update { $0.state = .failed("\(error)") }
          return continuation.resume(throwing: error)
        }
        self.hub = hub
        hub.onChange = { [weak self] in self?.scheduleStatus() }
        var address = configuration.listen
        if configuration.local { address.host = "127.0.0.1" }
        let transport = makeTransport(address)
        transport.onFailure = { [weak self, weak hub] error in
          guard let self, let hub, self.hub === hub else { return }
          configuration.log("Hub stopped listening: \(error)")
          hub.stop()
          self.hub = nil
          update { $0.state = .failed("\(error)") }
        }
        hub.start(transport: transport) { [self] result in
          switch result {
          case .success(let port):
            update { $0.port = port }
            if configuration.pairsAtStart { _ = hub.startPairing() }
            refreshStatus(running: true)
            configuration.log("Hub \(hub.hubKey) listening on \(ListenAddress(host: address.host, port: port))")
            continuation.resume(returning: port)
          case .failure(let error):
            hub.stop()
            self.hub = nil
            update { $0.state = .failed("\(error)") }
            continuation.resume(throwing: HubServerError.listen("\(error)"))
          }
        }
      }
    }
  }

  /// Closes every connection, stops listening and writes pending changes
  public func stop() async {
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
      queue.async { [self] in
        hub?.stop()
        hub = nil
        update { $0 = Status(state: .stopped, hubKey: $0.hubKey, name: $0.name, local: configuration.local) }
        continuation.resume()
      }
    }
  }

  /// A new pairing code replacing the old one (owners do this with `hub/pair/new`). Not in local mode.
  public func newPairingCode() async throws -> PairingCode {
    let hub = try await running()
    guard !configuration.local else { throw ChannelFailure("no pairing in local mode") }
    let code = hub.pairing.queue.sync { hub.pairing.create() }
    update { $0.pairingCode = code }
    queue.async { hub.announce(code) }
    return code
  }

  /// Writes a new pairing code to a data directory, as `hub-server --pair` does: a hub running on that directory
  /// takes it at once
  public static func writePairingCode(dataDirectory: URL) throws -> PairingCode {
    try FileManager.default.createDirectory(at: dataDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return Pairing(directory: dataDirectory, log: { print($0) }).create()
  }

  /// Adds a key or device SPKI to the owners group
  public func addOwner(_ key: String) async throws {
    let hub = try await running()
    queue.async {
      hub.security.addOwner(key)
      hub.connectionsChanged()
    }
  }

  /// `hub://pair?a=<address>&c=<code>`, for a link or QR code that the Hub app opens
  public static func pairingLink(address: String, code: String) -> URL {
    var components = URLComponents()
    components.scheme = "hub"
    components.host = "pair"
    components.queryItems = [URLQueryItem(name: "a", value: address), URLQueryItem(name: "c", value: code)]
    return components.url!
  }

  private func running() async throws -> Hub {
    try await withCheckedThrowingContinuation { continuation in
      queue.async { [self] in
        guard let hub else { return continuation.resume(throwing: HubServerError.notRunning) }
        continuation.resume(returning: hub)
      }
    }
  }

  private func makeTransport(_ address: ListenAddress) -> ChannelTransport {
    #if canImport(Network)
    WebSocketServer(address)
    #else
    fatalError("HubServer needs a ByteStreamListener on this platform")
    #endif
  }

  // MARK: Status

  private var statusScheduled = false
  /// On the queue: hub changes come in bursts
  private func scheduleStatus() {
    guard !statusScheduled else { return }
    statusScheduled = true
    queue.asyncAfter(deadline: .now() + 0.05) { [weak self] in
      self?.statusScheduled = false
      self?.refreshStatus(running: false)
    }
  }

  private func refreshStatus(running: Bool) {
    guard let hub else { return }
    let pairingCode = configuration.local ? nil : hub.pairing.displayed
    update { status in
      if running { status.state = .running }
      status.hubKey = hub.hubKey
      status.name = hub.name
      status.connections = hub.connections.count
      status.peers = hub.connections.map { connection in
        Peer(id: connection.id, name: connection.name, device: connection.device.flatMap { hub.registry.device($0)?.name },
          key: connection.key, address: connection.ip, services: connection.services.count)
      }
      status.owners = hub.security.members.members(ownersGroup).count
      status.pairingCode = pairingCode
    }
  }

  private func update(_ change: (inout Status) -> Void) {
    lock.withLock {
      let old = _status
      change(&_status)
      guard _status != old else { return }
      for observer in observers.values { observer.yield(_status) }
    }
  }
}
