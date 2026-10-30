#if canImport(Network)
import Foundation
import Network
import Security

/// Channel over QUIC (`Channel/channel/docs/quic.md`) with Network.framework: ALPN `channel/1`, one bidirectional
/// stream per connection carrying the WebSocket's text messages, each prefixed with its length as a QUIC
/// variable-length integer. The first frame is `{"hello": headers}`, used like the upgrade request's headers. No
/// 0-RTT. Run it next to a `WebSocketServer`: browsers and most ports only speak WebSocket.
@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
public final class QUICServer: ChannelTransport {
  public struct Options: Sendable {
    /// Largest incoming message in bytes, bigger ones close the connection. 16 MiB like channel TS.
    public var maxPayload: Int = 16 * 1024 * 1024
    /// Milliseconds without any packet before QUIC closes the connection; clients send a keepalive every 15 s
    public var idleTimeout: Int = 30_000
    public init() {}
  }

  public static let alpn = "channel/1"
  public let address: ListenAddress
  public var onFailure: ((Error) -> Void)?
  private let identity: SecIdentity
  private let options: Options
  private var listener: NWListener?
  private var connections: [ObjectIdentifier: QUICConnection] = [:]

  /// `identity` is the server's certificate and private key
  public init(_ address: ListenAddress, identity: SecIdentity, options: Options = Options()) {
    self.address = address
    self.identity = identity
    self.options = options
  }

  /// The certificate and key from a PKCS#12 file, for example
  /// `openssl pkcs12 -export -inkey key.pem -in cert.pem -out server.p12 -passout pass:secret`. The key stays in
  /// memory: before macOS 15 the import would add it to the login keychain, so there it throws; pass a `SecIdentity`.
  public convenience init(_ address: ListenAddress, pkcs12: Data, password: String, options: Options = Options()) throws {
    var settings: [String: Any] = [kSecImportExportPassphrase as String: password]
    if #available(macOS 15, iOS 18, tvOS 18, watchOS 11, visionOS 2, *) {
      settings[kSecImportToMemoryOnly as String] = true
    } else {
      #if os(macOS)
      throw ChannelFailure("a PKCS#12 import needs macOS 15, older ones add the key to the login keychain")
      #endif
    }
    var items: CFArray?
    let status = SecPKCS12Import(pkcs12 as CFData, settings as CFDictionary, &items)
    guard status == errSecSuccess, let item = (items as? [[String: Any]])?.first,
          let value = item[kSecImportItemIdentity as String] else {
      throw ChannelFailure("can't read the PKCS#12 identity (\(status))")
    }
    self.init(address, identity: value as! SecIdentity, options: options)
  }

  public func start(queue: DispatchQueue, accept: @escaping UpgradeHandler, ready: @escaping (Result<UInt16, Error>) -> Void) {
    let quic = NWProtocolQUIC.Options(alpn: [Self.alpn])
    quic.direction = .bidirectional
    quic.idleTimeout = options.idleTimeout
    // One stream per connection: the client's first, no unidirectional ones
    quic.initialMaxStreamsBidirectional = 1
    quic.initialMaxStreamsUnidirectional = 0
    let security = quic.securityProtocolOptions
    sec_protocol_options_set_min_tls_protocol_version(security, .TLSv13)
    if let identity = sec_identity_create(identity) {
      sec_protocol_options_set_local_identity(security, identity)
    }
    let parameters = NWParameters(quic: quic)
    parameters.allowLocalEndpointReuse = true
    let listener: NWListener
    do {
      let port = NWEndpoint.Port(rawValue: address.port) ?? .any
      if let host = address.host {
        parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: port)
        listener = try NWListener(using: parameters)
      } else {
        listener = try NWListener(using: parameters, on: port)
      }
    } catch {
      ready(.failure(error))
      return
    }
    self.listener = listener
    var reported = false
    listener.stateUpdateHandler = { [weak self, weak listener] state in
      switch state {
      case .ready:
        guard !reported else { return }
        reported = true
        ready(.success(listener?.port?.rawValue ?? self?.address.port ?? 0))
      case .failed(let error):
        listener?.cancel()
        if !reported {
          reported = true
          ready(.failure(error))
        } else {
          self?.onFailure?(error)
        }
      case .waiting(let error):
        if !reported {
          reported = true
          listener?.cancel()
          ready(.failure(error))
        }
      default:
        break
      }
    }
    listener.newConnectionGroupHandler = { [weak self] group in
      guard let self else { return group.cancel() }
      let connection = QUICConnection(group: group, queue: queue, maxPayload: self.options.maxPayload, accept: accept)
      let id = ObjectIdentifier(connection)
      self.connections[id] = connection
      connection.onFinish = { [weak self] in self?.connections[id] = nil }
      connection.start()
    }
    listener.start(queue: queue)
  }

  public func stop() {
    listener?.cancel()
    listener = nil
    let connections = self.connections.values
    self.connections = [:]
    for connection in connections { connection.close() }
  }
}

/// One QUIC connection: its first stream, framed. Everything runs on the server's queue.
@available(macOS 12, iOS 15, tvOS 15, watchOS 8, *)
final class QUICConnection: MessageConnection {
  var onMessage: ((String) -> Void)?
  var onClose: (() -> Void)?
  var onFinish: (() -> Void)?
  private let group: NWConnectionGroup
  private let queue: DispatchQueue
  private let maxPayload: Int
  private var accept: UpgradeHandler?
  private var stream: NWConnection?
  private var buffer = Data()
  private var isOpen = false
  private var isClosed = false

  init(group: NWConnectionGroup, queue: DispatchQueue, maxPayload: Int, accept: @escaping UpgradeHandler) {
    self.group = group
    self.queue = queue
    self.maxPayload = maxPayload
    self.accept = accept
  }

  func start() {
    group.stateUpdateHandler = { [weak self] state in
      switch state {
      case .failed, .cancelled: self?.close()
      default: break
      }
    }
    group.newConnectionHandler = { [weak self] stream in
      // Later streams are refused
      guard let self, self.stream == nil, !self.isClosed else { return stream.cancel() }
      self.stream = stream
      stream.stateUpdateHandler = { [weak self] state in
        switch state {
        case .failed, .cancelled: self?.close()
        default: break
        }
      }
      stream.start(queue: self.queue)
      self.receive(stream)
    }
    group.start(queue: queue)
  }

  private func receive(_ stream: NWConnection) {
    stream.receive(minimumIncompleteLength: 1, maximumLength: 256 * 1024) { [weak self] data, _, isComplete, error in
      guard let self, !self.isClosed else { return }
      if let data, !data.isEmpty {
        self.buffer.append(data)
        self.frames()
      }
      if isComplete || error != nil {
        self.close()
      } else if !self.isClosed {
        self.receive(stream)
      }
    }
  }

  /// Hands over the complete frames in the buffer; the first one is the hello
  private func frames() {
    var offset = buffer.startIndex
    while !isClosed, offset < buffer.endIndex {
      let size = 1 << (buffer[offset] >> 6)
      guard buffer.endIndex - offset >= size else { break }
      var length = UInt64(buffer[offset] & 0x3f)
      for i in 1..<size { length = length << 8 | UInt64(buffer[offset + i]) }
      guard length <= UInt64(maxPayload) else { return close() }
      guard UInt64(buffer.endIndex - offset - size) >= length else { break }
      let start = offset + size
      let text = String(decoding: buffer[start..<start + Int(length)], as: UTF8.self)
      offset = start + Int(length)
      // An empty frame is a keepalive
      guard length > 0 else { continue }
      if isOpen {
        onMessage?(text)
      } else {
        hello(text)
      }
    }
    guard !isClosed else { return }
    buffer.removeSubrange(buffer.startIndex..<offset)
  }

  private func hello(_ text: String) {
    guard let accept, case .object(let object)? = try? JSON.parse(text), case .object(let fields)? = object["hello"] else {
      return close()
    }
    self.accept = nil
    var headers = [String: String]()
    for (name, value) in fields {
      if case .string(let value) = value { headers[name.lowercased()] = value }
    }
    let request = UpgradeRequest(method: "QUIC", headers: headers, remoteAddress: stream.flatMap { remoteAddress(of: $0.endpoint) })
    do {
      let open = try accept(request)
      isOpen = true
      open(self)
    } catch {
      // A refused state closes the connection, as there is no reply to the hello
      close()
    }
  }

  func send(_ text: String) {
    guard isOpen, !isClosed, let stream else { return }
    stream.send(content: Self.frame(Data(text.utf8)), completion: .contentProcessed { _ in })
  }

  static func frame(_ payload: Data) -> Data {
    let n = UInt64(payload.count)
    var frame: Data
    switch n {
    case ..<(1 << 6): frame = Data([UInt8(n)])
    case ..<(1 << 14): frame = Data([UInt8(n >> 8) | 0x40, UInt8(n & 0xff)])
    case ..<(1 << 30): frame = Data((0..<4).reversed().map { UInt8(truncatingIfNeeded: n >> ($0 * 8)) }); frame[0] |= 0x80
    default: frame = Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: n >> ($0 * 8)) }); frame[0] |= 0xc0
    }
    frame.append(payload)
    return frame
  }

  func close() {
    guard !isClosed else { return }
    isClosed = true
    stream?.cancel()
    group.cancel()
    let onClose = self.onClose
    self.onClose = nil
    self.onMessage = nil
    if isOpen { onClose?() }
    onFinish?()
    onFinish = nil
  }
}
#endif
