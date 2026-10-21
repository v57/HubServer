#if canImport(Network)
import Foundation
import Network

/// TCP with Network.framework
public final class NetworkStreamListener: ByteStreamListener {
  public let address: ListenAddress
  public var onFailure: ((Error) -> Void)?
  private var listener: NWListener?
  private var streams: [ObjectIdentifier: NetworkStream] = [:]

  public init(_ address: ListenAddress) {
    self.address = address
  }

  public func start(queue: DispatchQueue, ready: @escaping (Result<UInt16, Error>) -> Void, accept: @escaping (ByteStream) -> Void) {
    let tcp = NWProtocolTCP.Options()
    tcp.noDelay = true
    let parameters = NWParameters(tls: nil, tcp: tcp)
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
        // The port is taken or the network isn't up: report it instead of waiting forever
        if !reported {
          reported = true
          listener?.cancel()
          ready(.failure(error))
        }
      default:
        break
      }
    }
    listener.newConnectionHandler = { [weak self] connection in
      guard let self else {
        connection.cancel()
        return
      }
      let stream = NetworkStream(connection, queue: queue)
      let id = ObjectIdentifier(stream)
      self.streams[id] = stream
      stream.onFinish = { [weak self] in self?.streams[id] = nil }
      accept(stream)
    }
    listener.start(queue: queue)
  }

  public func stop() {
    listener?.cancel()
    listener = nil
    let streams = self.streams.values
    self.streams = [:]
    for stream in streams { stream.close() }
  }
}

final class NetworkStream: ByteStream {
  private let connection: NWConnection
  private let queue: DispatchQueue
  private var onData: ((Data) -> Void)?
  private var onClose: (() -> Void)?
  var onFinish: (() -> Void)?
  private var isClosed = false

  init(_ connection: NWConnection, queue: DispatchQueue) {
    self.connection = connection
    self.queue = queue
  }

  var remoteAddress: String? {
    guard case .hostPort(let host, _) = connection.endpoint else { return nil }
    var text: String
    switch host {
    case .ipv4(let address): text = "\(address)"
    case .ipv6(let address): text = "\(address)"
    case .name(let name, _): text = name
    @unknown default: text = "\(host)"
    }
    // Drop the interface scope (`fe80::1%en0`), and show IPv4-mapped addresses as IPv4
    if let percent = text.firstIndex(of: "%") { text = String(text[..<percent]) }
    if text.hasPrefix("::ffff:"), text.contains(".") { text = String(text.dropFirst(7)) }
    return text
  }

  func start(onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
    self.onData = onData
    self.onClose = onClose
    connection.stateUpdateHandler = { [weak self] state in
      switch state {
      case .failed, .cancelled: self?.finish()
      default: break
      }
    }
    connection.start(queue: queue)
    receive()
  }

  private func receive() {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 256 * 1024) { [weak self] data, _, isComplete, error in
      guard let self, !self.isClosed else { return }
      if let data, !data.isEmpty { self.onData?(data) }
      if isComplete || error != nil {
        self.close()
      } else if !self.isClosed {
        self.receive()
      }
    }
  }

  func write(_ data: Data) {
    guard !isClosed else { return }
    connection.send(content: data, completion: .contentProcessed { _ in })
  }

  func close() {
    guard !isClosed else { return }
    // Sends what is queued, then the FIN, then releases the connection
    connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [connection] _ in
      connection.cancel()
    })
    queue.asyncAfter(deadline: .now() + 2) { [connection] in connection.cancel() }
    finish()
  }

  private func finish() {
    guard !isClosed else { return }
    isClosed = true
    let onClose = self.onClose
    self.onClose = nil
    self.onData = nil
    onClose?()
    onFinish?()
    onFinish = nil
  }
}
#endif
