#if !canImport(Network) && canImport(Glibc)
import Foundation
import Glibc

/// TCP on POSIX sockets, where Network.framework is missing (Linux): a non-blocking listening socket and
/// connections driven by dispatch sources on the listener's queue.
public final class SocketStreamListener: ByteStreamListener {
  public let address: ListenAddress
  public var onFailure: ((Error) -> Void)?
  private var descriptor: Int32 = -1
  private var source: DispatchSourceRead?
  private var streams: [ObjectIdentifier: SocketStream] = [:]

  public init(_ address: ListenAddress) {
    self.address = address
  }

  public func start(queue: DispatchQueue, ready: @escaping (Result<UInt16, Error>) -> Void, accept: @escaping (ByteStream) -> Void) {
    let descriptor: Int32
    do {
      descriptor = try Self.listen(address)
    } catch {
      ready(.failure(error))
      return
    }
    self.descriptor = descriptor
    let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
    source.setEventHandler { [weak self] in
      guard let self else { return }
      while true {
        let client = Glibc.accept(descriptor, nil, nil)
        guard client >= 0 else { break }
        SocketStream.configure(client)
        let stream = SocketStream(client, queue: queue)
        let id = ObjectIdentifier(stream)
        self.streams[id] = stream
        stream.onFinish = { [weak self] in self?.streams[id] = nil }
        accept(stream)
      }
    }
    source.setCancelHandler { close(descriptor) }
    self.source = source
    source.resume()
    ready(.success(Self.port(of: descriptor) ?? address.port))
  }

  public func stop() {
    source?.cancel()
    source = nil
    descriptor = -1
    let streams = self.streams.values
    self.streams = [:]
    for stream in streams { stream.close() }
  }

  /// A listening socket on the address: IPv6 with IPv4-mapped addresses for every interface, else the address's family
  private static func listen(_ address: ListenAddress) throws -> Int32 {
    var storage = sockaddr_storage()
    var length: socklen_t
    let family: Int32
    if let host = address.host {
      var hints = addrinfo()
      hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE
      hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
      var info: UnsafeMutablePointer<addrinfo>?
      guard getaddrinfo(host, String(address.port), &hints, &info) == 0, let first = info else {
        throw SocketError("invalid listen address \(address)")
      }
      defer { freeaddrinfo(info) }
      family = first.pointee.ai_family
      length = first.pointee.ai_addrlen
      withUnsafeMutableBytes(of: &storage) { $0.copyMemory(from: UnsafeRawBufferPointer(start: first.pointee.ai_addr, count: Int(length))) }
    } else {
      var any = sockaddr_in6()
      any.sin6_family = sa_family_t(AF_INET6)
      any.sin6_port = address.port.bigEndian
      any.sin6_addr = in6addr_any
      family = AF_INET6
      length = socklen_t(MemoryLayout<sockaddr_in6>.size)
      withUnsafeMutableBytes(of: &storage) { $0.copyMemory(from: withUnsafeBytes(of: any) { $0 }) }
    }
    let descriptor = socket(family, Int32(SOCK_STREAM.rawValue), 0)
    guard descriptor >= 0 else { throw SocketError.errno("socket") }
    var on: Int32 = 1
    var off: Int32 = 0
    setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &on, socklen_t(MemoryLayout<Int32>.size))
    if family == AF_INET6 && address.host == nil {
      setsockopt(descriptor, Int32(IPPROTO_IPV6), IPV6_V6ONLY, &off, socklen_t(MemoryLayout<Int32>.size))
    }
    let bound = withUnsafePointer(to: &storage) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, length) }
    }
    guard bound == 0, Glibc.listen(descriptor, 128) == 0 else {
      let error = SocketError.errno("bind \(address)")
      close(descriptor)
      throw error
    }
    _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK)
    return descriptor
  }

  private static func port(of descriptor: Int32) -> UInt16? {
    var storage = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let result = withUnsafeMutablePointer(to: &storage) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
    }
    guard result == 0 else { return nil }
    return withUnsafeBytes(of: storage) { bytes in
      // sin_port and sin6_port sit at the same offset, in network order
      UInt16(bigEndian: bytes.load(fromByteOffset: 2, as: UInt16.self))
    }
  }
}

final class SocketStream: ByteStream {
  private let descriptor: Int32
  private let queue: DispatchQueue
  private var readSource: DispatchSourceRead?
  private var writeSource: DispatchSourceWrite?
  private var pending = Data()
  private var onData: ((Data) -> Void)?
  private var onClose: (() -> Void)?
  var onFinish: (() -> Void)?
  private var isClosing = false
  private var isFinished = false
  let remoteAddress: String?

  init(_ descriptor: Int32, queue: DispatchQueue) {
    self.descriptor = descriptor
    self.queue = queue
    remoteAddress = Self.peer(descriptor)
  }

  static func configure(_ descriptor: Int32) {
    var on: Int32 = 1
    setsockopt(descriptor, Int32(IPPROTO_TCP), TCP_NODELAY, &on, socklen_t(MemoryLayout<Int32>.size))
    _ = fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK)
  }

  func start(onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
    self.onData = onData
    self.onClose = onClose
    let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
    source.setEventHandler { [weak self] in self?.read() }
    readSource = source
    source.resume()
  }

  private func read() {
    var buffer = [UInt8](repeating: 0, count: 256 * 1024)
    while !isFinished {
      let count = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, 0) }
      if count > 0 {
        onData?(Data(buffer[0..<count]))
      } else if count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        finish()
        return
      } else if errno != EINTR {
        return
      }
    }
  }

  func write(_ data: Data) {
    guard !isClosing, !isFinished else { return }
    pending.append(data)
    flush()
  }

  /// Writes what the socket takes now, and waits for it to take the rest
  private func flush() {
    while !pending.isEmpty, !isFinished {
      let count = pending.withUnsafeBytes { send(descriptor, $0.baseAddress, $0.count, Int32(MSG_NOSIGNAL)) }
      if count > 0 {
        pending.removeFirst(count)
      } else if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
        waitForWritable()
        return
      } else if count < 0 && errno == EINTR {
        continue
      } else {
        finish()
        return
      }
    }
    if pending.isEmpty, isClosing { finish() }
  }

  private func waitForWritable() {
    guard writeSource == nil else { return }
    let source = DispatchSource.makeWriteSource(fileDescriptor: descriptor, queue: queue)
    source.setEventHandler { [weak self] in
      guard let self else { return }
      self.writeSource?.cancel()
      self.writeSource = nil
      self.flush()
    }
    writeSource = source
    source.resume()
  }

  func close() {
    guard !isClosing, !isFinished else { return }
    isClosing = true
    if pending.isEmpty {
      finish()
    } else {
      // Gives up on a peer that doesn't read
      queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.finish() }
    }
  }

  private func finish() {
    guard !isFinished else { return }
    isFinished = true
    writeSource?.cancel()
    writeSource = nil
    let descriptor = self.descriptor
    if let readSource {
      readSource.setCancelHandler { Glibc.close(descriptor) }
      readSource.cancel()
    } else {
      Glibc.close(descriptor)
    }
    readSource = nil
    pending = Data()
    let onClose = self.onClose
    self.onClose = nil
    onData = nil
    onClose?()
    onFinish?()
    onFinish = nil
  }

  /// The peer's IP address, IPv4-mapped addresses shown as IPv4
  private static func peer(_ descriptor: Int32) -> String? {
    var storage = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let result = withUnsafeMutablePointer(to: &storage) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(descriptor, $0, &length) }
    }
    guard result == 0 else { return nil }
    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    let named = withUnsafePointer(to: &storage) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        getnameinfo($0, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
      }
    }
    guard named == 0 else { return nil }
    var text = String(cString: host)
    if let percent = text.firstIndex(of: "%") { text = String(text[..<percent]) }
    if text.hasPrefix("::ffff:"), text.contains(".") { text = String(text.dropFirst(7)) }
    return text
  }
}

struct SocketError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
  static func errno(_ call: String) -> SocketError {
    SocketError("\(call): \(String(cString: strerror(Glibc.errno)))")
  }
}
#endif
