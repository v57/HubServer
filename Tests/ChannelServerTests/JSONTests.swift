import XCTest
@testable import ChannelServer

final class JSONTests: XCTestCase {
  func testRoundTrip() throws {
    let text = #"{"b":1,"a":[true,false,null,-2,2.5,1e-7,"x"],"c":{"d":{}},"e":[]}"#
    let value = try JSON.parse(text)
    XCTAssertEqual(value["b"], .int(1))
    XCTAssertEqual(value["a"]?.array?[4], .double(2.5))
    XCTAssertEqual(value["a"]?.array?[5].double, 1e-7)
    // Key order is kept
    XCTAssertEqual(value.object?.keys, ["b", "a", "c", "e"])
    XCTAssertEqual(try JSON.parse(value.text), value)
  }

  func testStrings() throws {
    let value = try JSON.parse(#""a\"b\\c\/d\n\t\u0001é🚀""#)
    XCTAssertEqual(value.string, "a\"b\\c/d\n\t\u{01}é🚀")
    XCTAssertEqual(value.text, #""a\"b\\c/d\n\t\u0001é🚀""#)
    // A lone surrogate becomes U+FFFD
    XCTAssertEqual(try JSON.parse(#""\ud83d""#).string, "\u{FFFD}")
    XCTAssertEqual(JSON.string("кириллица").text, "\"кириллица\"")
  }

  func testNumbers() throws {
    XCTAssertEqual(try JSON.parse("9007199254740993"), .int(9_007_199_254_740_993))
    XCTAssertEqual(try JSON.parse("-0"), .int(0))
    XCTAssertEqual(try JSON.parse("1.0").text, "1")
    XCTAssertEqual(try JSON.parse("1E3").double, 1000)
    XCTAssertEqual(JSON.double(0.1).text, "0.1")
    XCTAssertEqual(JSON.double(.nan).text, "null")
    XCTAssertEqual(JSON.double(3).int, 3)
    XCTAssertNil(JSON.double(3.5).int)
  }

  func testInvalid() {
    for text in ["", "{", "[1,]", "{\"a\"}", "tru", "01", "1.", "\"\u{01}\"", "[1] 2", "nul", "{'a':1}"] {
      XCTAssertThrowsError(try JSON.parse(text), text)
    }
    let deep = String(repeating: "[", count: 600) + String(repeating: "]", count: 600)
    XCTAssertThrowsError(try JSON.parse(deep))
  }

  func testObjectEditing() {
    var object: JSONObject = ["a": 1, "b": 2]
    object["a"] = 3
    object["c"] = 4
    object["b"] = nil
    XCTAssertEqual(object.keys, ["a", "c"])
    XCTAssertEqual(JSON.object(object).text, #"{"a":3,"c":4}"#)
    XCTAssertEqual(JSON.object(object).prettyText, "{\n  \"a\": 3,\n  \"c\": 4\n}")
    // Nil values in literals are left out
    let optional: String? = nil
    XCTAssertEqual(JSON(dictionaryLiteral: ("x", JSON(optional)), ("y", nil)).text, #"{"x":null}"#)
  }
}

final class WebSocketTests: XCTestCase {
  func testSHA1() {
    let hex = SHA1.hash(Array("abc".utf8)).map { String(format: "%02x", $0) }.joined()
    XCTAssertEqual(hex, "a9993e364706816aba3e25717850c26c9cd0d89d")
    // RFC 6455 section 1.3
    let accept = Data(SHA1.hash(Array("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11".utf8))).base64EncodedString()
    XCTAssertEqual(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
  }

  func testUpgradeRequest() {
    let request = WebSocketConnection.parseRequest("GET /ws?auth=a%2Bb&v=1&flag HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nAuth: header\r\nX-A: 1\r\nx-a: 2")!
    XCTAssertEqual(request.path, "/ws")
    XCTAssertEqual(request.query, ["auth": "a+b", "v": "1", "flag": ""])
    XCTAssertEqual(request.headers["upgrade"], "websocket")
    XCTAssertEqual(request.headers["x-a"], "1, 2")
    // Headers win over query parameters
    XCTAssertEqual(request.channelHeaders["auth"], "header")
    XCTAssertEqual(request.channelHeaders["v"], "1")
  }

  func testListenAddress() {
    XCTAssertEqual(ListenAddress("1997"), ListenAddress(port: 1997))
    XCTAssertEqual(ListenAddress("127.0.0.1:2000"), ListenAddress(host: "127.0.0.1", port: 2000))
    XCTAssertEqual(ListenAddress("[::1]:2000"), ListenAddress(host: "::1", port: 2000))
    XCTAssertNil(ListenAddress("nope"))
  }

  func testFramesAndPeer() throws {
    let stream = FakeStream()
    var received: [String] = []
    var closed = false
    let connection = WebSocketConnection(stream: stream, options: .init()) { request in
      XCTAssertEqual(request.headers["auth"], "token")
      return { connection in
        connection.onMessage = { received.append($0) }
        connection.onClose = { closed = true }
      }
    }
    connection.start()
    stream.feed("GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nauth: token\r\n\r\n")
    XCTAssertTrue(stream.written.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="))
    // A masked text frame split across reads, then a fragmented message, a ping and a large frame
    let frame = masked(opcode: 0x1, Array("hello".utf8))
    stream.feed(Data(frame.prefix(3)))
    stream.feed(Data(frame.dropFirst(3)))
    stream.feed(Data(masked(opcode: 0x1, Array("frag".utf8), fin: false) + masked(opcode: 0x9, [7]) + masked(opcode: 0x0, Array("ment".utf8))))
    let large = String(repeating: "z", count: 70000)
    stream.feed(Data(masked(opcode: 0x1, Array(large.utf8))))
    XCTAssertEqual(received, ["hello", "fragment", large])
    // The pong echoes the ping
    XCTAssertEqual(stream.frames.last, [0x8A, 1, 7])
    connection.send("hi")
    XCTAssertEqual(stream.frames.last, [0x81, 2] + Array("hi".utf8))
    // An unmasked frame is a protocol error
    stream.feed(Data([0x81, 1, 0x41]))
    XCTAssertTrue(closed)
    XCTAssertTrue(stream.isClosed)
  }

  func testRefusedUpgrade() {
    let stream = FakeStream()
    let connection = WebSocketConnection(stream: stream, options: .init()) { _ in throw ChannelFailure("no") }
    connection.start()
    stream.feed("GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: a\r\nSec-WebSocket-Version: 13\r\n\r\n")
    XCTAssertTrue(stream.written.hasPrefix("HTTP/1.1 401"))
    XCTAssertTrue(stream.isClosed)
  }

  private func masked(opcode: UInt8, _ payload: [UInt8], fin: Bool = true) -> [UInt8] {
    let mask: [UInt8] = [1, 2, 3, 4]
    var frame: [UInt8] = [(fin ? 0x80 : 0) | opcode]
    if payload.count < 126 {
      frame.append(0x80 | UInt8(payload.count))
    } else if payload.count <= 0xFFFF {
      frame += [0x80 | 126, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)]
    } else {
      frame.append(0x80 | 127)
      for shift in stride(from: 56, through: 0, by: -8) { frame.append(UInt8((payload.count >> shift) & 0xFF)) }
    }
    frame += mask
    frame += payload.enumerated().map { $0.element ^ mask[$0.offset & 3] }
    return frame
  }
}

final class FakeStream: ByteStream {
  var remoteAddress: String? { "127.0.0.1" }
  var onData: ((Data) -> Void)?
  var onClose: (() -> Void)?
  var output = Data()
  var frames: [[UInt8]] = []
  var isClosed = false
  var written: String { String(decoding: output, as: UTF8.self) }
  func start(onData: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
    self.onData = onData
    self.onClose = onClose
  }
  func write(_ data: Data) {
    output.append(data)
    frames.append(Array(data))
  }
  func close() {
    isClosed = true
  }
  func feed(_ text: String) { feed(Data(text.utf8)) }
  func feed(_ data: Data) { onData?(data) }
}

final class PeerTests: XCTestCase {
  final class Pipe: MessageConnection {
    var onMessage: ((String) -> Void)?
    var onClose: (() -> Void)?
    var sent: [JSON] = []
    func send(_ text: String) { sent.append(try! JSON.parse(text)) }
    func close() { onClose?() }
  }

  func testPostsStreamsAndCancel() throws {
    let router = ChannelRouter()
    var cancelled = 0
    var pending: IncomingCall?
    router
      .post("echo") { $0.body }
      .post("wait", answering: { call in
        pending = call
        call.onCancel { cancelled += 1 }
      })
      .stream("count") { stream in
        stream.send(1)
        stream.send(2)
        stream.finish()
      }
      .stream("open") { stream in stream.onCancel { cancelled += 1 } }
    let pipe = Pipe()
    let peer = ChannelPeer(connection: pipe, handler: router)
    peer.receive(#"[{"id":1,"path":"echo","body":{"a":1}},{"path":"echo"},{"id":2,"stream":"count"},{"id":3,"path":"nope"}]"#)
    XCTAssertEqual(pipe.sent.map(\.text), [
      #"{"id":1,"body":{"a":1}}"#, #"{"id":2,"body":1}"#, #"{"id":2,"body":2}"#, #"{"id":2,"done":true}"#,
      #"{"id":3,"error":"api not found","code":"not_found"}"#,
    ])
    pipe.sent = []
    peer.receive(#"{"id":4,"path":"wait"}"#)
    peer.receive(#"{"cancel":4}"#)
    XCTAssertEqual(cancelled, 1)
    XCTAssertEqual(pipe.sent.map(\.text), [#"{"id":4,"error":"cancelled","code":"cancelled"}"#])
    pending?.respond("late")
    XCTAssertEqual(pipe.sent.count, 1)
    peer.receive(#"{"id":5,"stream":"open"}"#)
    peer.receive(#"{"cancel":5}"#)
    XCTAssertEqual(cancelled, 2)
    XCTAssertEqual(pipe.sent.count, 1)
  }

  func testOutgoingRequests() throws {
    let pipe = Pipe()
    let peer = ChannelPeer(connection: pipe, handler: nil)
    var results: [Result<JSON?, ChannelFailure>] = []
    var events: [String] = []
    peer.request("a", body: 1, context: ["hub": 1]) { results.append($0) }
    peer.request("b") { results.append($0) }
    let stream = peer.stream("s") { event in
      switch event {
      case .value(let value): events.append(value?.text ?? "none")
      case .done: events.append("done")
      case .failure(let failure): events.append("error \(failure.message)")
      }
    }
    XCTAssertEqual(pipe.sent[0].text, #"{"id":0,"path":"a","body":1,"context":{"hub":1}}"#)
    XCTAssertEqual(pipe.sent[2].text, #"{"id":2,"stream":"s"}"#)
    peer.receive(#"{"id":0,"body":"ok"}"#)
    peer.receive(#"{"id":1,"error":"banned","code":403,"info":{"x":1}}"#)
    peer.receive(#"{"id":2,"body":5}"#)
    peer.receive(#"{"id":2,"body":6}"#)
    XCTAssertEqual(try results[0].get(), "ok")
    guard case .failure(let failure) = results[1] else { return XCTFail() }
    XCTAssertEqual(failure, ChannelFailure("banned", code: 403, info: ["x": 1]))
    XCTAssertEqual(events, ["5", "6"])
    peer.cancel(stream)
    XCTAssertEqual(pipe.sent.last?.text, #"{"cancel":2}"#)
    peer.receive(#"{"id":2,"body":7}"#)
    XCTAssertEqual(events, ["5", "6"])
    // Pending requests fail with disconnected when the connection closes
    peer.request("c") { results.append($0) }
    pipe.close()
    guard case .failure(let disconnected) = results[2] else { return XCTFail() }
    XCTAssertEqual(disconnected.code, "disconnected")
  }
}
