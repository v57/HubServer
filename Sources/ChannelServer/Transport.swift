import Foundation

// Two layers, so other platforms can plug in where they can:
// - `ChannelTransport`: message connections with the upgrade request's headers. The channel server and the hub only
//   use this. `WebSocketServer` implements it on top of any `ByteStreamListener`.
// - `ByteStreamListener`: plain TCP. `NetworkStreamListener` (Network.framework) on Apple platforms; Linux and
//   Windows ports add one on sockets, or replace the whole `ChannelTransport` with their own WebSocket server.

/// The HTTP request that asked for a WebSocket
public struct UpgradeRequest: Sendable {
  public var method: String
  /// URL path without the query
  public var path: String
  /// Query parameters, decoded
  public var query: [String: String]
  /// Header names in lowercase
  public var headers: [String: String]
  /// IP address of the client
  public var remoteAddress: String?

  public init(method: String = "GET", path: String = "/", query: [String: String] = [:], headers: [String: String] = [:], remoteAddress: String? = nil) {
    self.method = method
    self.path = path
    self.query = query
    self.headers = headers
    self.remoteAddress = remoteAddress
  }

  /// What a channel server's `state()` sees: query parameters (browsers send headers that way), then the headers,
  /// then `x-hub-remote-ip`
  public var channelHeaders: [String: String] {
    var result = query
    for (name, value) in headers { result[name] = value }
    if let remoteAddress { result["x-hub-remote-ip"] = remoteAddress }
    return result
  }
}

/// One open connection that carries text messages
public protocol MessageConnection: AnyObject {
  /// Called on the transport's queue for every text message
  var onMessage: ((String) -> Void)? { get set }
  /// Called on the transport's queue once, when the connection closed for any reason
  var onClose: (() -> Void)? { get set }
  func send(_ text: String)
  func close()
}

/// The answer to an upgrade request: refuse it, or accept and get the connection once it is open
public typealias UpgradeHandler = (UpgradeRequest) throws -> (MessageConnection) -> Void

/// Accepts message connections. Everything is called on the queue passed to `start`.
public protocol ChannelTransport: AnyObject {
  /// Starts listening. `accept` throwing refuses the request (HTTP 401). `ready` gets the port or the error.
  func start(queue: DispatchQueue, accept: @escaping UpgradeHandler, ready: @escaping (Result<UInt16, Error>) -> Void)
  /// Stops listening and closes every connection
  func stop()
}

/// A TCP connection
public protocol ByteStream: AnyObject {
  var remoteAddress: String? { get }
  /// Starts reading. Both callbacks run on the listener's queue; `onClose` runs once.
  func start(onData: @escaping (Data) -> Void, onClose: @escaping () -> Void)
  func write(_ data: Data)
  /// Closes after the pending writes
  func close()
}

/// Accepts TCP connections
public protocol ByteStreamListener: AnyObject {
  func start(queue: DispatchQueue, ready: @escaping (Result<UInt16, Error>) -> Void, accept: @escaping (ByteStream) -> Void)
  func stop()
}

/// Where to listen: a port on every interface, or one address
public struct ListenAddress: Sendable, Equatable, CustomStringConvertible {
  /// `nil` listens on every interface
  public var host: String?
  /// 0 picks a free port
  public var port: UInt16
  public init(host: String? = nil, port: UInt16) {
    self.host = host
    self.port = port
  }
  /// `1997`, `127.0.0.1:1997` or `[::1]:1997`
  public init?(_ text: String) {
    if let port = UInt16(text) {
      self.init(port: port)
      return
    }
    guard let colon = text.lastIndex(of: ":"), let port = UInt16(text[text.index(after: colon)...]) else { return nil }
    var host = String(text[..<colon])
    if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    self.init(host: host.isEmpty ? nil : host, port: port)
  }
  public var description: String {
    guard let host else { return "\(port)" }
    return host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
  }
}
