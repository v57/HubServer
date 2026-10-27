import Foundation

/// A WebSocket server (RFC 6455, text messages, no extensions) on top of any `ByteStreamListener`
public final class WebSocketServer: ChannelTransport {
  public struct Options: Sendable {
    /// Largest incoming message in bytes, bigger ones close the connection (1009). 16 MiB like channel TS.
    public var maxPayload: Int = 16 * 1024 * 1024
    /// Seconds without any incoming data before the connection is closed. The server pings at a third of it.
    public var idleTimeout: TimeInterval = 120
    public init() {}
  }
  private let listener: ByteStreamListener
  private let options: Options
  public var onFailure: ((Error) -> Void)? {
    get { listener.onFailure }
    set { listener.onFailure = newValue }
  }
  private var connections: [ObjectIdentifier: WebSocketConnection] = [:]
  private var timer: DispatchSourceTimer?
  private var queue: DispatchQueue?

  public init(listener: ByteStreamListener, options: Options = Options()) {
    self.listener = listener
    self.options = options
  }

  #if canImport(Network)
  /// Network.framework TCP on `address`
  public convenience init(_ address: ListenAddress, options: Options = Options()) {
    self.init(listener: NetworkStreamListener(address), options: options)
  }
  #elseif canImport(Glibc)
  /// POSIX sockets on `address`
  public convenience init(_ address: ListenAddress, options: Options = Options()) {
    self.init(listener: SocketStreamListener(address), options: options)
  }
  #endif

  public func start(queue: DispatchQueue, accept: @escaping UpgradeHandler, ready: @escaping (Result<UInt16, Error>) -> Void) {
    self.queue = queue
    listener.start(queue: queue, ready: ready) { [weak self] stream in
      guard let self else {
        stream.close()
        return
      }
      let connection = WebSocketConnection(stream: stream, options: self.options, accept: accept)
      let id = ObjectIdentifier(connection)
      self.connections[id] = connection
      connection.onFinish = { [weak self] in self?.connections[id] = nil }
      connection.start()
    }
    let timer = DispatchSource.makeTimerSource(queue: queue)
    let interval = max(options.idleTimeout / 3, 1)
    timer.schedule(deadline: .now() + interval, repeating: interval)
    timer.setEventHandler { [weak self] in
      guard let self else { return }
      let now = Date()
      for connection in self.connections.values { connection.keepAlive(now: now) }
    }
    timer.resume()
    self.timer = timer
  }

  public func stop() {
    timer?.cancel()
    timer = nil
    listener.stop()
    let connections = self.connections.values
    self.connections = [:]
    for connection in connections { connection.close(code: 1001) }
  }
}

final class WebSocketConnection: MessageConnection {
  var onMessage: ((String) -> Void)?
  var onClose: (() -> Void)?
  var onFinish: (() -> Void)?
  private let stream: ByteStream
  private let options: WebSocketServer.Options
  private var accept: UpgradeHandler?
  private var buffer: [UInt8] = []
  private var offset = 0
  private var isOpen = false
  private var isClosed = false
  /// Fragments of a message in progress
  private var fragments: [UInt8]?
  private var lastActivity = Date()

  init(stream: ByteStream, options: WebSocketServer.Options, accept: @escaping UpgradeHandler) {
    self.stream = stream
    self.options = options
    self.accept = accept
  }

  func start() {
    stream.start(onData: { [weak self] data in self?.received(data) }, onClose: { [weak self] in self?.finish() })
  }

  // MARK: Sending

  func send(_ text: String) {
    guard isOpen, !isClosed else { return }
    stream.write(Self.frame(opcode: 0x1, payload: Array(text.utf8)))
  }

  func close() {
    close(code: 1000)
  }

  func close(code: UInt16) {
    guard !isClosed else { return }
    if isOpen { stream.write(Self.frame(opcode: 0x8, payload: [UInt8(code >> 8), UInt8(code & 0xFF)])) }
    stream.close()
    finish()
  }

  /// Pings an idle connection and closes one that stayed silent for `idleTimeout`
  func keepAlive(now: Date) {
    let idle = now.timeIntervalSince(lastActivity)
    if !isOpen {
      // A client that never finished its upgrade request
      if idle > 10 { close(code: 1000) }
    } else if idle > options.idleTimeout {
      close(code: 1001)
    } else if idle >= options.idleTimeout / 3 {
      stream.write(Self.frame(opcode: 0x9, payload: []))
    }
  }

  private func finish() {
    guard !isClosed else { return }
    isClosed = true
    let wasOpen = isOpen
    isOpen = false
    let onClose = self.onClose
    self.onClose = nil
    self.onMessage = nil
    if wasOpen { onClose?() }
    onFinish?()
    onFinish = nil
  }

  static func frame(opcode: UInt8, payload: [UInt8]) -> Data {
    var frame = Data()
    frame.reserveCapacity(payload.count + 10)
    frame.append(0x80 | opcode)
    let count = payload.count
    if count < 126 {
      frame.append(UInt8(count))
    } else if count <= 0xFFFF {
      frame.append(126)
      frame.append(UInt8(count >> 8))
      frame.append(UInt8(count & 0xFF))
    } else {
      frame.append(127)
      for shift in stride(from: 56, through: 0, by: -8) { frame.append(UInt8((UInt64(count) >> UInt64(shift)) & 0xFF)) }
    }
    frame.append(contentsOf: payload)
    return frame
  }

  // MARK: Receiving

  private func received(_ data: Data) {
    guard !isClosed else { return }
    lastActivity = Date()
    if offset > 0, offset >= buffer.count / 2 {
      buffer.removeFirst(offset)
      offset = 0
    }
    buffer.append(contentsOf: data)
    if !isOpen {
      guard readUpgrade() else { return }
    }
    readFrames()
  }

  /// Handles the HTTP upgrade request once it is complete. Returns true when the connection is open.
  private func readUpgrade() -> Bool {
    guard let end = headerEnd() else {
      if buffer.count - offset > 16 * 1024 { respond(status: "431 Request Header Fields Too Large") }
      return false
    }
    let head = String(decoding: buffer[offset..<end], as: UTF8.self)
    offset = end + 4
    guard var request = Self.parseRequest(head) else {
      respond(status: "400 Bad Request")
      return false
    }
    request.remoteAddress = stream.remoteAddress
    let isUpgrade = request.headers["upgrade"]?.lowercased() == "websocket"
      && (request.headers["connection"]?.lowercased().contains("upgrade") ?? false)
    guard isUpgrade, request.method == "GET", let key = request.headers["sec-websocket-key"] else {
      // Like Bun's fetch fallback for plain HTTP requests
      respond(status: "200 OK")
      return false
    }
    guard request.headers["sec-websocket-version"] == "13" else {
      respond(status: "426 Upgrade Required", extra: "sec-websocket-version: 13\r\n")
      return false
    }
    let opened: (MessageConnection) -> Void
    do {
      guard let accept else { return false }
      opened = try accept(request)
    } catch {
      respond(status: "401 Unauthorized", body: "unauthorized")
      return false
    }
    accept = nil
    let digest = SHA1.hash(Array((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8))
    let response = "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: \(Data(digest).base64EncodedString())\r\n\r\n"
    stream.write(Data(response.utf8))
    isOpen = true
    opened(self)
    return !isClosed
  }

  private func headerEnd() -> Int? {
    var index = offset
    while index + 3 < buffer.count {
      if buffer[index] == 13, buffer[index + 1] == 10, buffer[index + 2] == 13, buffer[index + 3] == 10 { return index }
      index += 1
    }
    return nil
  }

  private func respond(status: String, body: String = "", extra: String = "") {
    let response = "HTTP/1.1 \(status)\r\ncontent-length: \(body.utf8.count)\r\ncontent-type: text/plain;charset=utf-8\r\nconnection: close\r\n\(extra)\r\n\(body)"
    stream.write(Data(response.utf8))
    stream.close()
    finish()
  }

  static func parseRequest(_ head: String) -> UpgradeRequest? {
    let lines = head.components(separatedBy: "\r\n")
    let parts = lines.first?.split(separator: " ", omittingEmptySubsequences: true) ?? []
    guard parts.count >= 2 else { return nil }
    var request = UpgradeRequest(method: String(parts[0]))
    let target = String(parts[1])
    if let question = target.firstIndex(of: "?") {
      request.path = String(target[..<question])
      for pair in target[target.index(after: question)...].split(separator: "&") {
        let pieces = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        let name = Self.decodeQuery(String(pieces[0]))
        guard !name.isEmpty else { continue }
        request.query[name] = pieces.count > 1 ? Self.decodeQuery(String(pieces[1])) : ""
      }
    } else {
      request.path = target
    }
    for line in lines.dropFirst() {
      guard let colon = line.firstIndex(of: ":") else { continue }
      let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
      let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
      if let existing = request.headers[name] {
        request.headers[name] = existing + ", " + value
      } else {
        request.headers[name] = value
      }
    }
    return request
  }

  private static func decodeQuery(_ text: String) -> String {
    let spaced = text.replacingOccurrences(of: "+", with: " ")
    return spaced.removingPercentEncoding ?? spaced
  }

  private func readFrames() {
    while !isClosed {
      let available = buffer.count - offset
      guard available >= 2 else { return }
      let first = buffer[offset]
      let second = buffer[offset + 1]
      let fin = first & 0x80 != 0
      let opcode = first & 0x0F
      let masked = second & 0x80 != 0
      var length = Int(second & 0x7F)
      var header = 2
      if length == 126 {
        guard available >= 4 else { return }
        length = Int(buffer[offset + 2]) << 8 | Int(buffer[offset + 3])
        header = 4
      } else if length == 127 {
        guard available >= 10 else { return }
        var value: UInt64 = 0
        for index in 0..<8 { value = value << 8 | UInt64(buffer[offset + 2 + index]) }
        guard value <= UInt64(options.maxPayload) else { return close(code: 1009) }
        length = Int(value)
        header = 10
      }
      guard first & 0x70 == 0 else { return close(code: 1002) }
      guard masked else { return close(code: 1002) }
      guard length <= options.maxPayload else { return close(code: 1009) }
      guard available >= header + 4 + length else { return }
      let mask = Array(buffer[(offset + header)..<(offset + header + 4)])
      let start = offset + header + 4
      var payload = Array(buffer[start..<(start + length)])
      for index in 0..<payload.count { payload[index] ^= mask[index & 3] }
      offset = start + length
      handleFrame(fin: fin, opcode: opcode, payload: payload)
    }
  }

  private func handleFrame(fin: Bool, opcode: UInt8, payload: [UInt8]) {
    switch opcode {
    case 0x0:
      guard fragments != nil else { return close(code: 1002) }
      fragments!.append(contentsOf: payload)
      guard fragments!.count <= options.maxPayload else { return close(code: 1009) }
      if fin {
        let message = fragments!
        fragments = nil
        deliver(message)
      }
    case 0x1, 0x2:
      guard fragments == nil else { return close(code: 1002) }
      if opcode == 0x2 {
        // Binary messages are ignored, also their fragments
        if !fin {
          fragments = []
          ignoreFragments = true
        }
        return
      }
      ignoreFragments = false
      if fin {
        deliver(payload)
      } else {
        fragments = payload
      }
    case 0x8:
      // Answers with the same code, then closes
      let code: UInt16 = payload.count >= 2 ? UInt16(payload[0]) << 8 | UInt16(payload[1]) : 1000
      close(code: code == 1005 || code == 1006 || code == 1015 ? 1000 : code)
    case 0x9:
      stream.write(Self.frame(opcode: 0xA, payload: payload))
    case 0xA:
      break
    default:
      close(code: 1002)
    }
  }
  private var ignoreFragments = false

  private func deliver(_ bytes: [UInt8]) {
    if ignoreFragments {
      ignoreFragments = false
      return
    }
    guard let text = String(bytes: bytes, encoding: .utf8) else { return close(code: 1007) }
    onMessage?(text)
  }
}

/// SHA-1, only for `Sec-WebSocket-Accept`
enum SHA1 {
  static func hash(_ message: [UInt8]) -> [UInt8] {
    var h: [UInt32] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0]
    var data = message
    let bitLength = UInt64(message.count) * 8
    data.append(0x80)
    while data.count % 64 != 56 { data.append(0) }
    for shift in stride(from: 56, through: 0, by: -8) { data.append(UInt8((bitLength >> UInt64(shift)) & 0xFF)) }
    var w = [UInt32](repeating: 0, count: 80)
    for chunk in stride(from: 0, to: data.count, by: 64) {
      for i in 0..<16 {
        let j = chunk + i * 4
        w[i] = UInt32(data[j]) << 24 | UInt32(data[j + 1]) << 16 | UInt32(data[j + 2]) << 8 | UInt32(data[j + 3])
      }
      for i in 16..<80 {
        let value = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
        w[i] = value << 1 | value >> 31
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4]
      for i in 0..<80 {
        let f: UInt32
        let k: UInt32
        switch i {
        case 0..<20: f = (b & c) | (~b & d); k = 0x5A82_7999
        case 20..<40: f = b ^ c ^ d; k = 0x6ED9_EBA1
        case 40..<60: f = (b & c) | (b & d) | (c & d); k = 0x8F1B_BCDC
        default: f = b ^ c ^ d; k = 0xCA62_C1D6
        }
        let temp = (a << 5 | a >> 27) &+ f &+ e &+ k &+ w[i]
        e = d
        d = c
        c = b << 30 | b >> 2
        b = a
        a = temp
      }
      h[0] = h[0] &+ a
      h[1] = h[1] &+ b
      h[2] = h[2] &+ c
      h[3] = h[3] &+ d
      h[4] = h[4] &+ e
    }
    return h.flatMap { [UInt8($0 >> 24), UInt8($0 >> 16 & 0xFF), UInt8($0 >> 8 & 0xFF), UInt8($0 & 0xFF)] }
  }
}
