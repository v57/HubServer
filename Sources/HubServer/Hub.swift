import ChannelServer
import Foundation

/// The hub: connections, service routing and the built-in APIs (protocol.md). Confined to `queue`.
final class Hub: @unchecked Sendable {
  let queue: DispatchQueue
  let configuration: HubServer.Configuration
  let storage: Storage
  let key: HubKeyPair
  let security: Security
  let registry: DeviceRegistry
  let pairing: Pairing
  let live: LiveValues
  let router = ChannelRouter()
  let log: (String) -> Void

  /// Open connections, oldest first
  private(set) var connections: [HubConnection] = []
  private var services: [String: ServiceGroup] = [:]
  private var serviceOrder: [String] = []
  /// Built-in paths and the paths that have providers
  private var api = Set<String>()
  private let apps = Apps()
  private var requests = 0
  /// The device this hub runs on
  private(set) var selfId: String?
  /// Connections that asked for the reporter role, oldest first; the first attached one of a device reports
  private var reporterCandidates: [HubConnection] = []
  /// Latest live data per device, in memory only
  private var liveData: [String: JSON] = [:]
  private let headerStore: JSONStore
  private(set) var name: String
  let network: NetworkAPI
  let netNode: NetNodeStore
  /// `hub/net/test/complete` results, in memory
  var testResults: [String: JSON] = [:]
  var onChange: () -> Void = {}

  var hubKey: String { security.hubKey }

  init(configuration: HubServer.Configuration, queue: DispatchQueue, log: @escaping (String) -> Void) throws {
    self.configuration = configuration
    self.queue = queue
    self.log = log
    storage = Storage(directory: configuration.dataDirectory, queue: queue, log: log)
    try FileManager.default.createDirectory(at: configuration.dataDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let keyURL = storage.url("auth")
    let keyExisted = FileManager.default.fileExists(atPath: keyURL.path)
    // A hub that ran before had its key file, even without `hub.json`
    let ranBefore = keyExisted || FileManager.default.fileExists(atPath: storage.url("hub.json").path)
    key = try HubKeyPair.loadOrCreate(keyURL)
    security = Security(storage: storage, hubKey: key.publicKey)
    registry = DeviceRegistry(storage: storage)
    pairing = Pairing(directory: configuration.dataDirectory, log: log)
    live = LiveValues(queue: queue)
    network = NetworkAPI(storage: storage, security: security, key: key, queue: queue)
    netNode = NetNodeStore(storage: storage)
    headerStore = storage.store("header.json")
    name = configuration.name ?? HubServer.Configuration.hostName

    security.load(hubKeyExisted: ranBefore)
    security.launcher = configuration.launcherKey
    security.local = configuration.local
    for owner in configuration.owners { security.addOwner(owner) }
    registry.load()
    // Lost tombstones would let revoked devices and keys back in
    if registry.store.corrupt { security.lockDown() }
    headerStore.encode = { [unowned self] in ["name": .string(name)] }
    if headerStore.load({ json in
      guard let name = json["name"]?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty else {
        throw ChannelFailure("invalid header")
      }
      self.name = name
    }) == false {
      headerStore.writeNow()
    }
    security.deviceName = { [unowned self] id in registry.device(id)?.name }
    network.localAgentEndpoint = configuration.localAgentEndpoint ?? LocalAgent.defaultEndpoint
    network.load()
    netNode.load()
    for (path, name) in networkAPINames { security.names.register(path, name: name) }
    observeChanges()
    observeNetwork()
    enrolSelf()
    registerRoutes()
    api = router.routes
  }

  // MARK: Lifecycle

  private var transport: ChannelTransport?

  func start(transport: ChannelTransport, ready: @escaping (Result<UInt16, Error>) -> Void) {
    self.transport = transport
    router.onConnect = { [unowned self] peer in connected(peer) }
    router.onDisconnect = { [unowned self] peer in disconnected(peer) }
    router.listen(transport, queue: queue, state: { [unowned self] request in try accept(request) }, ready: ready)
  }

  func stop() {
    router.stop()
    transport = nil
    storage.flush()
  }

  /// The hub's own device, approved, with the hub key as its service
  private func enrolSelf() {
    guard let deviceKey = configuration.devicePublicKey, HubCrypto.publicKey(spki: deviceKey) != nil else { return }
    let id = HubCrypto.deviceId(spki: deviceKey)
    selfId = id
    let now = Int(Date().timeIntervalSince1970)
    let certificate = Certificate(device: deviceKey, deviceId: id, service: hubKey, instance: configuration.instance,
      deviceName: configuration.deviceName ?? HubServer.Configuration.hostName, platform: configuration.platform, parent: nil, iat: now, exp: now)
    _ = registry.seen(certificate, approve: true)
    registry.place(certificate, name: nil)
  }

  /// At connect: checks the token, refuses revoked keys and keeps a valid certificate, attaching it if approved
  private func accept(_ request: UpgradeRequest) throws -> HubConnection {
    let headers = request.channelHeaders
    let key = try security.verifyToken(headers["auth"], version: headers["v"])
    let connection = HubConnection(key: key, ip: headers["x-hub-remote-ip"])
    guard let key else { return connection }
    if registry.isKeyRevoked(key) { throw ChannelFailure("key revoked") }
    guard let header = headers["device"], !header.isEmpty else { return connection }
    switch verifyCertificate(header, serviceKey: key, hubKey: hubKey) {
    case .invalid(let reason):
      log("Ignored device certificate of \(key): \(reason)")
    case .valid(let certificate):
      let id = certificate.deviceId
      let approve = security.isOwner(Principal(key: key)) || security.isOwner(Principal(device: id))
        || (security.launcher != nil && key == security.launcher) || id == selfId
      guard let device = registry.seen(certificate, approve: approve) else {
        log("Ignored certificate of revoked device \(id)")
        return connection
      }
      connection.certificate = certificate
      if device.approved { attach(connection) }
      live.changed(.pending)
    }
    return connection
  }

  /// Makes a connection with a certificate from an approved device a device connection
  private func attach(_ connection: HubConnection) {
    guard let certificate = connection.certificate else { return }
    connection.device = certificate.deviceId
    connection.instance = certificate.instance
    if let moved = registry.place(certificate, name: connection.name) {
      log("Service \(certificate.service) moved from device \(moved) to \(certificate.deviceId)")
    }
  }

  private func connected(_ peer: ChannelPeer) {
    let connection = peer.state as! HubConnection
    connection.peer = peer
    connection.isOpen = true
    connections.append(connection)
    connectionsChanged()
  }

  private func disconnected(_ peer: ChannelPeer) {
    let connection = peer.state as! HubConnection
    connection.isOpen = false
    connections.removeAll { $0 === connection }
    removeServices(connection, Array(connection.services))
    let hadApps = !connection.apps.isEmpty
    apps.removeAll(connection)
    reporterCandidates.removeAll { $0 === connection }
    if hadApps { live.changed(.badges) }
    network.disconnected(connection)
    connectionsChanged()
  }

  private func observeChanges() {
    security.grants.onChange = { [unowned self] changed in
      network.grantsChanged(changed)
      live.changed(.grants, .groups)
      connectionsChanged()
    }
    security.members.onChange = { [unowned self] group in
      network.groupMembershipChanged(group)
      live.changed(.groups)
      connectionsChanged()
    }
    security.groups.onChange = { [unowned self] in live.changed(.groups) }
    security.names.onChange = { [unowned self] in live.changed(.groups, .api) }
    security.host.onPendingChange = { [unowned self] in live.changed(.hostPending, .badges) }
    security.whitelist.onChange = { [unowned self] in live.changed(.whitelist) }
    registry.onChange = { [unowned self] in
      live.changed(.devices, .pending)
      onChange()
    }
  }

  /// Connections, their devices or their groups changed
  func connectionsChanged() {
    live.changed(.connections, .devices, .status, .badges, .providers, .api, .netList)
    onChange()
  }

  func connection(_ peer: ChannelPeer) -> HubConnection { peer.state as! HubConnection }
  func caller(_ peer: ChannelPeer) -> Caller { security.caller(connection(peer).principal) }

  // MARK: Services

  private func group(_ path: String) -> ServiceGroup {
    if let group = services[path] { return group }
    let group = ServiceGroup(path: path, queue: queue)
    if let balancer = security.settings.balancer(path).flatMap(LoadBalancer.Kind.init(rawValue:)) { group.setBalancer(balancer) }
    services[path] = group
    serviceOrder.append(path)
    return group
  }

  private func addServices(_ connection: HubConnection, _ paths: [String]) {
    for path in paths where !path.isEmpty && !connection.services.contains(path) {
      connection.services.insert(path)
      let enabled = security.allowsHost(connection.principal, path)
      if group(path).add(Provider(connection: connection, enabled: enabled)) { api.insert(path) }
    }
  }

  private func removeServices(_ connection: HubConnection, _ paths: [String]) {
    for path in paths where connection.services.contains(path) {
      connection.services.remove(path)
      if services[path]?.remove(connection) == true { api.remove(path) }
    }
  }

  /// The client's context with `hub` replaced by the caller (protocol.md section 4)
  private func forwardedContext(_ context: JSON, _ caller: Caller) -> JSON {
    var object = context.object ?? [:]
    object["hub"] = nil
    object["hub"] = ["caller": caller.json, "hubKey": .string(hubKey)]
    return .object(object)
  }

  /// Picks a provider for a call to a service path, now or once one is free (hub-server 7461b70: waiting calls are
  /// served oldest first and fail with `api not available` after 30 s). Returns what stops waiting, when it waits.
  private func provider(for path: String, peer: ChannelPeer, context: JSON,
    _ use: @escaping (ServiceGroup, Result<Provider, ChannelFailure>) -> Void) throws -> (() -> Void)? {
    guard let group = services[path] else { throw ChannelFailure.apiNotFound }
    let caller = self.caller(peer)
    guard security.allowsCall(caller, path, isPublic: group.isPublic) else { throw ChannelFailure("permissions required") }
    if let provider = try group.select(context) ?? group.next() {
      use(group, .success(provider))
      return nil
    }
    let id = group.wait(limit: security.settings.pendingLimit, resolve: { provider in
      group.claimed(provider)
      use(group, .success(provider))
    }, fail: { use(group, .failure($0)) })
    live.changed(.status)
    return { group.cancelWait(id) }
  }

  private var nextToken = 0
  private func token() -> Int {
    nextToken += 1
    return nextToken
  }

  private func forward(_ call: IncomingCall) throws {
    let context = forwardedContext(call.context, caller(call.peer))
    let stopWaiting = try provider(for: call.path, peer: call.peer, context: call.context) { [unowned self] group, result in
      let provider: Provider
      switch result {
      case .success(let found): provider = found
      case .failure(let failure): return call.fail(failure)
      }
      guard !call.isCancelled, !call.isFinished else { return group.completed(provider) }
      group.requests += 1
      requests += 1
      live.changed(.status)
      let token = self.token()
      guard let peer = provider.connection.peer else { return call.fail(.cancelled) }
      let id = peer.request(call.path, body: call.body, context: context) { [unowned self] result in
        guard provider.running.removeValue(forKey: token) != nil else { return }
        switch result {
        case .success(let body): call.respond(body)
        // The provider went away: like hub-server, the caller gets `cancelled`
        case .failure(let failure): call.fail(failure.code == "disconnected" ? .cancelled : failure)
        }
        group.completed(provider)
        live.changed(.status)
      }
      provider.running[token] = {
        peer.cancel(id)
        call.fail(.cancelled)
      }
      call.onCancel { [unowned self] in
        guard provider.running.removeValue(forKey: token) != nil else { return }
        peer.cancel(id)
        group.completed(provider)
        live.changed(.status)
      }
    }
    if let stopWaiting { call.onCancel(stopWaiting) }
  }

  private func forward(_ stream: IncomingStream) throws {
    let context = forwardedContext(stream.context, caller(stream.peer))
    let stopWaiting = try provider(for: stream.path, peer: stream.peer, context: stream.context) { [unowned self] group, result in
      let provider: Provider
      switch result {
      case .success(let found): provider = found
      case .failure(let failure): return stream.fail(failure)
      }
      guard !stream.isFinished else { return group.completed(provider) }
      group.requests += 1
      requests += 1
      live.changed(.status)
      let token = self.token()
      guard let peer = provider.connection.peer else { return stream.fail(.cancelled) }
      let id = peer.stream(stream.path, body: stream.body, context: context) { [unowned self] event in
        switch event {
        case .value(let value):
          stream.send(value)
          return
        case .done:
          stream.finish()
        case .failure(let failure):
          stream.fail(failure.code == "disconnected" ? .cancelled : failure)
        }
        guard provider.running.removeValue(forKey: token) != nil else { return }
        group.completed(provider)
        live.changed(.status)
      }
      provider.running[token] = {
        peer.cancel(id)
        stream.fail(.cancelled)
      }
      stream.onCancel { [unowned self] in
        guard provider.running.removeValue(forKey: token) != nil else { return }
        peer.cancel(id)
        group.completed(provider)
        live.changed(.status)
      }
    }
    if let stopWaiting { stream.onCancel(stopWaiting) }
  }

  /// Connections providing a path
  func providers(of path: String) -> [HubConnection] {
    services[path]?.providers.map(\.connection) ?? []
  }

  /// Providers of a path the caller may call, for `hub/api/services`
  private func providers(_ path: String?, principal: Principal) -> JSON {
    guard let path, api.contains(path), let group = services[path] else { return [] }
    guard security.allowsCall(security.caller(principal), path, isPublic: group.isPublic) else { return [] }
    let list = group.providers.map { provider -> (label: String, json: JSON) in
      let connection = provider.connection
      var object: JSONObject = ["id": .string(connection.id)]
      if let key = connection.key { object["key"] = .string(key) }
      let name = connection.name?.trimmingCharacters(in: .whitespacesAndNewlines)
      if let name, !name.isEmpty { object["name"] = .string(name) }
      if let device = connection.device { object["device"] = ["id": .string(device), "name": .string(registry.device(device)?.name ?? device)] }
      if let instance = connection.instance { object["instance"] = .string(instance) }
      object["online"] = true
      return ((name?.isEmpty == false ? name! : connection.id), .object(object))
    }
    return .array(list.sorted { $0.label == $1.label ? ($0.json["id"]?.string ?? "") < ($1.json["id"]?.string ?? "") : $0.label < $1.label }.map(\.json))
  }

  /// Paths the caller may call, for `hub/api`
  private func allowedApi(_ caller: Caller) -> JSON {
    JSON(api.sorted().filter { path in
      builtinAccess(path) != nil ? security.allowsBuiltin(caller, path) : security.allowsCall(caller, path, isPublic: services[path]?.isPublic ?? false)
    })
  }

  // MARK: Devices

  private func deviceJSON(_ id: String) -> JSON? {
    guard let device = registry.device(id) else { return nil }
    let attached = connections.filter { $0.device == id }
    var services: [JSON] = []
    for key in registry.servicesOn(id) {
      guard let service = registry.services[key] else { continue }
      let states = attached.filter { $0.key == key }
      var paths: [String] = []
      for state in states {
        for path in state.services.sorted() where !paths.contains(path) { paths.append(path) }
      }
      var object: JSONObject = ["key": .string(key), "instance": .string(service.instance)]
      if let name = service.name { object["name"] = .string(name) }
      object["online"] = .bool(!states.isEmpty)
      object["paths"] = JSON(paths)
      services.append(.object(object))
    }
    var object: JSONObject = ["id": .string(id), "key": .string(device.key), "name": .string(device.name)]
    if let platform = device.platform { object["platform"] = .string(platform) }
    if let os = device.os { object["os"] = .string(os) }
    if let arch = device.arch { object["arch"] = .string(arch) }
    if let parent = device.parent { object["parent"] = .string(parent) }
    object["approved"] = .bool(device.approved)
    object["revoked"] = .bool(device.revoked != nil)
    object["online"] = .bool(!attached.isEmpty || id == selfId)
    if let state = network.deviceNetworkState(id) { object["network"] = .string(state) }
    if let overlay = network.deviceOverlay(id) { object["overlay"] = overlay }
    object["lastSeen"] = .string(id == selfId ? isoNow() : device.lastSeen)
    if let capabilities = device.capabilities { object["capabilities"] = capabilities }
    object["services"] = .array(services)
    return .object(object)
  }

  private var devicesJSON: JSON {
    .array(registry.order.compactMap(deviceJSON))
  }

  /// Approves a pending device and attaches its open connections
  @discardableResult
  func approve(_ id: String?) throws -> JSON {
    try registry.approve(id)
    for connection in connections where connection.certificate?.deviceId == id { attach(connection) }
    connectionsChanged()
    return deviceJSON(id!) ?? .null
  }

  /// Closes the device's connections and those of revoked keys, and drops their grants and group memberships
  private func cleanUp(_ id: String, revokedKeys: [String]) {
    liveData[id] = nil
    let revoked = Set(revokedKeys)
    for connection in connections where connection.certificate?.deviceId == id || connection.key.map(revoked.contains) == true {
      connection.peer?.close()
    }
    security.removeDevice(id)
    for key in revokedKeys { security.revokeKey(key) }
    network.removeDevice(id, revokedKeys: revokedKeys)
    connectionsChanged()
  }

  private func reporter(of id: String) -> HubConnection? {
    reporterCandidates.first { $0.device == id }
  }
  private func requireReporter(_ peer: ChannelPeer) throws -> String {
    let connection = connection(peer)
    guard let id = connection.device, reporter(of: id) === connection else { throw ChannelFailure("not the device reporter") }
    return id
  }

  private func describeDevice(_ peer: ChannelPeer, _ body: JSON?) throws {
    let id = try requireReporter(peer)
    guard let body = body?.object else { throw ChannelFailure("invalid description") }
    func text(_ value: JSON?, _ max: Int) -> Bool {
      guard let value else { return true }
      return value.string.map { $0.utf8.count <= max } ?? false
    }
    guard text(body["name"], 64), text(body["os"], 64), text(body["arch"], 32) else { throw ChannelFailure("invalid description") }
    let capabilities = body["capabilities"]
    if let capabilities {
      guard capabilities.object != nil else { throw ChannelFailure("invalid capabilities") }
      if capabilities.text.utf8.count > 65536 { throw ChannelFailure("capabilities too large") }
      try checkSSH(id, capabilities["ssh"])
    }
    try registry.update(id, name: body["name"]?.string, os: body["os"]?.string, arch: body["arch"]?.string, capabilities: capabilities)
  }

  /// `ssh.hostKey` and every `ssh.hostKeys` entry must carry the device's signature over `ssh1:<hostKey>`
  private func checkSSH(_ id: String, _ ssh: JSON?) throws {
    guard let ssh else { return }
    guard ssh.object != nil, ssh["port"]?.int != nil, case .int = ssh["port"]! else { throw ChannelFailure("invalid ssh capability") }
    if let hostKeys = ssh["hostKeys"], hostKeys.array == nil { throw ChannelFailure("invalid ssh capability") }
    let deviceKey = registry.device(id)!.key
    for entry in [ssh] + (ssh["hostKeys"]?.array ?? []) {
      guard let hostKey = entry["hostKey"]?.string, let signature = entry["hostKeySignature"]?.string else {
        throw ChannelFailure("invalid ssh capability")
      }
      guard HubCrypto.verify(signature: signature, message: "ssh1:\(hostKey)", spki: deviceKey) else {
        throw ChannelFailure("invalid ssh host key signature")
      }
    }
  }

  private func reportData(_ peer: ChannelPeer, _ body: JSON?) throws {
    let id = try requireReporter(peer)
    guard let body, body.object != nil else { throw ChannelFailure("invalid data") }
    if body.text.utf8.count > 16384 { throw ChannelFailure("data too large") }
    liveData[id] = body
    live.changed(.deviceData(id))
  }

  // MARK: Pairing

  /// At start: a code when the hub has no owners, see `Pairing.start`. None in local mode.
  func startPairing() -> PairingCode? {
    guard !configuration.local else { return nil }
    let needed = !security.hasOwners
    let code = pairing.queue.sync { pairing.start(needed: needed) }
    if let code { announce(code) }
    return code
  }

  func announce(_ code: PairingCode) {
    log("Pairing code: \(code.code) (valid until \(isoDate(code.expires)))")
    // Deletes the files once it expires, unless a newer code replaced it
    let delay = max(0, code.expires.timeIntervalSinceNow) + 1
    pairing.queue.asyncAfter(deadline: .now() + delay) { [pairing] in
      pairing.clearIfExpired()
    }
    onChange()
  }

  /// `hub/pair`: the key and, with a certificate, its device (approved) join the owners
  private func pair(_ call: IncomingCall) {
    let connection = connection(call.peer)
    guard let key = connection.key else { return call.fail(ChannelFailure("unauthorized")) }
    let code = call.body?["code"]
    pairing.queue.async { [pairing, queue, unowned self] in
      let result = pairing.verify(code)
      queue.async { [self] in
        switch result {
        case .failure(let failure):
          call.fail(failure)
        case .success:
          security.members.add(keyMember(key), to: ownersGroup)
          if let id = connection.certificate?.deviceId {
            _ = try? approve(id)
            security.members.add(deviceMember(id), to: ownersGroup)
          }
          connectionsChanged()
          log("Paired owner \(key)\(connection.certificate.map { " on device \($0.deviceId)" } ?? "")")
          call.respond(["owner": true, "hubKey": .string(hubKey), "name": .string(name)])
        }
      }
    }
  }

  // MARK: Routes

  private func registerRoutes() {
    router.check = { [unowned self] _, path, peer, _ in
      guard builtinAccess(path) != nil else { return }
      try security.checkBuiltin(caller(peer), path)
    }
    router.postOther { [unowned self] call in try forward(call) }
    router.streamOther { [unowned self] stream in try forward(stream) }
    registerHubRoutes()
    registerSecurityRoutes()
    registerDeviceRoutes()
    registerNetworkRoutes()
  }

  private func stream(_ stream: IncomingStream, _ topic: LiveTopic, _ compute: @escaping () throws -> JSON) throws {
    try live.stream(stream, topic: topic, compute: compute)
  }

  private func registerHubRoutes() {
    router
      .post("hub/info") { [unowned self] _ in
        ["key": .string(hubKey), "protocol": 1, "pro": true, "mode": .string(security.effectiveMode.rawValue)]
      }
      .post("hub/pair", answering: { [unowned self] call in pair(call) })
      .post("hub/pair/new", answering: { [unowned self] call in
        guard !configuration.local else { throw ChannelFailure("no pairing in local mode") }
        pairing.queue.async { [pairing, queue, unowned self] in
          let code = pairing.create()
          queue.async { [self] in
            announce(code)
            call.respond(["code": .string(code.code), "expires": .int(Int(code.expires.timeIntervalSince1970))])
          }
        }
      })
      .post("hub/api") { [unowned self] call in allowedApi(caller(call.peer)) }
      .stream("hub/api") { [unowned self] call in
        try stream(call, .api) { [unowned self] in allowedApi(caller(call.peer)) }
      }
      .stream("hub/api/services") { [unowned self] call in
        let principal = connection(call.peer).principal
        let path = call.body?.string
        try stream(call, .providers) { [unowned self] in providers(path, principal: principal) }
      }
      .post("hub/profile/update") { [unowned self] call in
        let connection = connection(call.peer)
        if let icon = call.body?["icon"], !icon.isNull { connection.icon = icon }
        if let name = call.body?["name"]?.string, !name.isEmpty { connection.name = name }
        connectionsChanged()
        return nil
      }
      .post("hub/service/update") { [unowned self] call in
        serviceUpdate(connection(call.peer), call.body)
        return nil
      }
      .post("hub/key") { [unowned self] _ in .string(hubKey) }
      .stream("hub/connections") { [unowned self] call in try stream(call, .connections) { [unowned self] in connectionsJSON } }
      .stream("hub/status") { [unowned self] call in try stream(call, .status) { [unowned self] in statusJSON } }
      .stream("hub/status/badges") { [unowned self] call in try stream(call, .badges) { [unowned self] in badgesJSON } }
      .stream("hub/header") { [unowned self] call in try stream(call, .header) { [unowned self] in ["name": .string(name)] } }
      .post("hub/header/set") { [unowned self] call in
        guard let value = call.body?["name"]?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty,
          value.unicodeScalars.count <= 128
        else { throw ChannelFailure("invalid_hub_header_name") }
        name = value
        headerStore.writeNow()
        live.changed(.header)
        onChange()
        return ["name": .string(value)]
      }
      .post("hub/balancer/set") { [unowned self] call in
        guard let path = call.body?["path"]?.string, let kind = call.body?["type"]?.string.flatMap(LoadBalancer.Kind.init(rawValue:)) else {
          throw ChannelFailure("invalid balancer")
        }
        security.settings.setBalancer(path, kind.rawValue)
        services[path]?.setBalancer(kind)
        live.changed(.status)
        return nil
      }
      .post("hub/balancer/limit") { [unowned self] call in
        guard let limit = call.body?["limit"]?.int, limit >= 0 else { throw ChannelFailure("invalid limit") }
        security.settings.setPendingLimit(limit)
        return nil
      }
      // Merging and proxies aren't supported here; the status stream answers so apps can show it
      .stream("hub/merge/status") { [unowned self] call in try stream(call, .status) { [] } }
  }

  private func serviceUpdate(_ connection: HubConnection, _ body: JSON?) {
    if body?["reporter"] == .bool(true), !reporterCandidates.contains(where: { $0 === connection }) {
      reporterCandidates.append(connection)
    }
    if let headers = body?["services"]?.array {
      let paths = headers.compactMap { $0["path"]?.string }
      let wanted = Set(paths)
      addServices(connection, paths.filter { !connection.services.contains($0) })
      removeServices(connection, connection.services.filter { !wanted.contains($0) })
      for header in headers {
        guard let path = header["path"]?.string, let group = services[path] else { continue }
        group.setPublic(connection, header["public"] == .bool(true))
        if let limit = header["limit"]?.int, limit >= 0 { group.setLimit(connection, limit) }
        if let permissions = header["permissions"]?.object, let permission = permissions["name"]?.string {
          let groupName = permissions["group"]?.string ?? String(path.split(separator: "/").first ?? "")
          security.names.add(path, name: "\(groupName): \(permission)")
        }
      }
    }
    if let headers = body?["apps"]?.array {
      let wanted = Set(headers.compactMap { $0["path"]?.string })
      apps.add(connection, headers.filter { ($0["path"]?.string).map { !connection.apps.contains($0) } ?? false })
      apps.remove(connection, connection.apps.filter { !wanted.contains($0) })
    }
    if let add = body?["add"]?.strings { addServices(connection, add) }
    if let remove = body?["remove"]?.strings { removeServices(connection, remove) }
    if let add = body?["addApps"]?.array { apps.add(connection, add) }
    if let remove = body?["removeApps"]?.strings { apps.remove(connection, remove) }
    connectionsChanged()
  }

  private var connectionsJSON: JSON {
    .array(connections.map { connection in
      var object: JSONObject = ["id": .string(connection.id)]
      if let key = connection.key { object["key"] = .string(key) }
      if let name = connection.name { object["name"] = .string(name) }
      if let icon = connection.icon { object["icon"] = icon }
      object["services"] = .int(connection.services.count)
      object["apps"] = .int(connection.apps.count)
      if let group = security.userGroup(connection.key) { object["group"] = .string(group) }
      if let device = connection.device {
        object["device"] = .string(device)
        if let instance = connection.instance { object["instance"] = .string(instance) }
      }
      return .object(object)
    })
  }

  private var statusJSON: JSON {
    ["requests": .int(requests), "services": .array(serviceOrder.compactMap { services[$0]?.status }), "pro": true]
  }

  private var badgesJSON: JSON {
    ["connections": .int(connections.count), "services": .int(services.count), "security": .int(security.host.pending.count),
     "apps": apps.json]
  }

  private func registerSecurityRoutes() {
    router
      .stream("hub/security/mode") { [unowned self] call in
        try stream(call, .security) { [unowned self] in
          ["mode": .string(security.effectiveMode.rawValue), "requireV1": .bool(security.requireV1)]
        }
      }
      .post("hub/security/mode/set") { [unowned self] call in
        try security.setMode(call.body)
        live.changed(.security)
        connectionsChanged()
        return nil
      }
      .stream("hub/grants") { [unowned self] call in try stream(call, .grants) { [unowned self] in .array(security.grants.grants.map(\.json)) } }
      .post("hub/grant/add") { [unowned self] call in try security.addGrant(call.body, by: caller(call.peer)).json }
      .post("hub/grant/remove") { [unowned self] call in
        guard security.grants.remove(id: call.body?["id"]?.string) != nil else { throw ChannelFailure("grant not found") }
        return nil
      }
      .post("hub/host/update") { [unowned self] call in
        guard let key = call.body?["key"]?.string else { throw ChannelFailure("invalid key") }
        let allow = call.body?["allow"]?.strings ?? []
        let revoke = call.body?["revoke"]?.strings ?? []
        security.host.allow(key, allow)
        security.host.revoke(key, revoke)
        for path in allow {
          if services[path]?.allowKey(key).enabled == true { api.insert(path) }
        }
        for path in revoke {
          if services[path]?.revokeKey(key).disabled == true { api.remove(path) }
        }
        connectionsChanged()
        return nil
      }
      .stream("hub/host/pending") { [unowned self] call in try stream(call, .hostPending) { [unowned self] in security.host.pending.json } }
      .post("hub/host/allowed") { [unowned self] call in JSON(call.body?.string.map { security.host.allowed.values($0) } ?? []) }
      .post("hub/call/update") { [unowned self] call in
        guard let key = call.body?["key"]?.string else { throw ChannelFailure("invalid key") }
        security.allowCalls(key, call.body?["allow"]?.strings ?? [], by: caller(call.peer).key ?? "owner")
        security.revokeCalls(key, call.body?["revoke"]?.strings ?? [])
        live.changed(.callPending)
        return nil
      }
      .stream("hub/call/pending") { [unowned self] call in try stream(call, .callPending) { [unowned self] in security.callPending.json } }
      .post("hub/call/allowed") { [unowned self] call in JSON(call.body?.string.map { security.grants.paths(.key($0)) } ?? []) }
      .post("hub/group/create") { [unowned self] call in .string(try security.groups.create(call.body)) }
      .post("hub/group/rename") { [unowned self] call in
        guard let group = call.body?["group"]?.string, let name = call.body?["name"]?.string else { throw ChannelFailure("invalid group") }
        if group == ownersGroup || name == ownersGroup { throw ChannelFailure("owners can not be renamed") }
        if name.trimmingCharacters(in: .whitespaces).isEmpty || security.groups.has(name) { throw ChannelFailure("invalid group") }
        guard security.groups.rename(group, to: name) else { return nil }
        security.members.renameGroup(group, to: name)
        security.grants.rename(.group(group), to: .group(name))
        network.groupRenamed(group, to: name)
        connectionsChanged()
        return nil
      }
      .post("hub/group/remove") { [unowned self] call in
        guard let group = call.body?.string else { throw ChannelFailure("invalid group") }
        if group == ownersGroup { throw ChannelFailure("owners can not be removed") }
        _ = security.groups.remove(group)
        security.members.removeGroup(group)
        security.grants.removeAll { $0.subject == .group(group) }
        network.groupMembershipChanged(group)
        return nil
      }
      .post("hub/group/update") { [unowned self] call in
        guard let group = call.body?["group"]?.string else { throw ChannelFailure("invalid group") }
        let by = caller(call.peer).key ?? "owner"
        var add = call.body?["add"]?.strings ?? []
        var remove = call.body?["remove"]?.strings ?? []
        if let set = call.body?["set"]?.strings {
          security.groups.ensure(group)
          let current = security.grants.paths(.group(group))
          add = set.filter { !current.contains($0) }
          remove = current.filter { !set.contains($0) }
        } else if !security.groups.has(group) {
          return nil
        }
        for path in add { security.grants.add(.group(group), .path(path), by: by) }
        let removed = Set(remove)
        security.grants.removeAll { grant in
          guard grant.subject == .group(group), case .path(let path) = grant.object else { return false }
          return removed.contains(path)
        }
        live.changed(.groups)
        return nil
      }
      .post("hub/group/update/users") { [unowned self] call in
        guard let group = call.body?["group"]?.string else { throw ChannelFailure("invalid group") }
        for user in call.body?["add"]?.strings ?? [] { security.members.add(memberString(user), to: group) }
        for user in call.body?["remove"]?.strings ?? [] { security.members.remove(memberString(user), from: group) }
        return nil
      }
      .stream("hub/group/list") { [unowned self] call in try stream(call, .groups) { [unowned self] in security.groupList } }
      .stream("hub/group/users") { [unowned self] call in try stream(call, .groups) { [unowned self] in security.groupUsers } }
      .stream("hub/group/names") { [unowned self] call in try stream(call, .groups) { [unowned self] in .object(security.names.names) } }
      .stream("hub/groups") { [unowned self] call in try stream(call, .groups) { [unowned self] in security.groupInfo } }
      .post("hub/whitelist") { [unowned self] call in
        let whitelist = security.whitelist
        whitelist.setEnabled(call.body?["enabled"]?.bool)
        for key in call.body?["add"]?.strings ?? [] { whitelist.add(key) }
        for key in call.body?["remove"]?.strings ?? [] { whitelist.remove(key) }
        if call.body?["allowsCurrent"] == .bool(true) {
          for connection in connections { if let key = connection.key { whitelist.add(key) } }
        }
        if whitelist.enabled {
          for connection in connections {
            guard let key = connection.key, security.isOwner(Principal(key: key)) || whitelist.contains(key) else {
              connection.peer?.close()
              continue
            }
          }
        }
        return nil
      }
      .stream("hub/whitelist/status") { [unowned self] call in try stream(call, .whitelist) { [unowned self] in security.whitelist.json } }
  }

  private func registerDeviceRoutes() {
    router
      .stream("hub/devices") { [unowned self] call in try stream(call, .devices) { [unowned self] in devicesJSON } }
      .stream("hub/devices/pending") { [unowned self] call in try stream(call, .pending) { [unowned self] in registry.pending } }
      .post("hub/device/approve") { [unowned self] call in try approve(call.body?["id"]?.string) }
      .post("hub/device/rename") { [unowned self] call in
        let id = call.body?["id"]?.string
        try registry.rename(id, call.body?["name"])
        connectionsChanged()
        return deviceJSON(id!)
      }
      .post("hub/device/remove") { [unowned self] call in
        let id = call.body?["id"]?.string
        try registry.remove(id)
        cleanUp(id!, revokedKeys: [])
        return nil
      }
      .post("hub/device/revoke") { [unowned self] call in
        let id = call.body?["id"]?.string
        let revokedKeys = try registry.revoke(id, keep: call.body?["keepServices"]?.strings ?? [])
        cleanUp(id!, revokedKeys: revokedKeys)
        return nil
      }
      .post("hub/device/describe") { [unowned self] call in
        try describeDevice(call.peer, call.body)
        return nil
      }
      .post("hub/device/data") { [unowned self] call in
        try reportData(call.peer, call.body)
        return nil
      }
      .stream("hub/devices/data") { [unowned self] call in
        guard let id = call.body?["id"]?.string, registry.device(id) != nil else { throw ChannelFailure("device not found") }
        try stream(call, .deviceData(id)) { [unowned self] in liveData[id] ?? [:] }
      }
  }
}
