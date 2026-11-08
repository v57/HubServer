import XCTest
@testable import ChannelServer

/// A connection that keeps what the peer wrote
private final class RecordingConnection: MessageConnection {
  var onMessage: ((String) -> Void)?
  var onClose: (() -> Void)?
  var sent: [JSON] = []
  func send(_ text: String) { sent.append(try! JSON.parse(text)) }
  func close() { onClose?() }
  func receive(_ text: String) { onMessage?(text) }
}

/// Keeps every stream and call, like the hub's live values and waiting calls do
private final class KeepingHandler: ChannelHandler {
  var streams: [IncomingStream] = []
  var calls: [IncomingCall] = []
  func peer(_ peer: ChannelPeer, post call: IncomingCall) { calls.append(call) }
  func peer(_ peer: ChannelPeer, stream call: IncomingStream) { streams.append(call) }
  func peer(_ peer: ChannelPeer, subscribe call: IncomingSubscription) {}
  func peerDisconnected(_ peer: ChannelPeer) {}
}

final class ChannelPeerTests: XCTestCase {
  /// Security audit H1: a second stream with the same id used to replace the first without ending it, and the first
  /// kept an unowned peer, so its next value after the disconnect trapped
  func testADuplicateStreamIdIsRefusedAndAStreamOutlivingItsPeerIsHarmless() {
    let handler = KeepingHandler()
    let connection = RecordingConnection()
    var peer: ChannelPeer? = ChannelPeer(connection: connection, handler: handler)
    connection.receive(#"{"id":1,"stream":"hub/status/badges"}"#)
    connection.receive(#"{"id":1,"stream":"hub/status/badges"}"#)
    XCTAssertEqual(handler.streams.count, 1)
    XCTAssertEqual(connection.sent.last?["error"]?.string, "id in use")
    connection.close()
    peer = nil
    XCTAssertNil(handler.streams[0].peer)
    // What the hub does on the next change of the topic
    handler.streams[0].send(["badges": 1])
    handler.streams[0].finish()
    XCTAssertEqual(connection.sent.count, 1)
    XCTAssertNil(peer)
  }

  func testADuplicateCallIdIsRefusedAndALateAnswerIsDropped() {
    let handler = KeepingHandler()
    let connection = RecordingConnection()
    var peer: ChannelPeer? = ChannelPeer(connection: connection, handler: handler)
    connection.receive(#"[{"id":7,"path":"slow"},{"id":7,"path":"slow"},{"id":7,"stream":"slow"}]"#)
    XCTAssertEqual(handler.calls.count, 1)
    XCTAssertEqual(handler.streams.count, 0)
    XCTAssertEqual(connection.sent.map { $0["error"]?.string }, ["id in use", "id in use"])
    connection.close()
    peer = nil
    handler.calls[0].respond("late")
    XCTAssertEqual(connection.sent.count, 2)
    XCTAssertNil(peer)
  }

  func testAnIdIsFreeAgainOnceItsCallIsAnswered() {
    let handler = KeepingHandler()
    let connection = RecordingConnection()
    let peer = ChannelPeer(connection: connection, handler: handler)
    connection.receive(#"{"id":1,"path":"a"}"#)
    handler.calls[0].respond("one")
    connection.receive(#"{"id":1,"path":"a"}"#)
    XCTAssertEqual(handler.calls.count, 2)
    XCTAssertEqual(connection.sent, [["id": 1, "body": "one"]])
    XCTAssertFalse(peer.isClosed)
  }

  func testOpenCallsAndStreamsPerConnectionAreCapped() {
    let handler = KeepingHandler()
    let connection = RecordingConnection()
    let peer = ChannelPeer(connection: connection, handler: handler)
    let half = ChannelPeer.maxOpenRequests / 2
    let calls = (0..<half).map { #"{"id":\#($0),"path":"slow"}"# }
    let streams = (half..<ChannelPeer.maxOpenRequests).map { #"{"id":\#($0),"stream":"slow"}"# }
    connection.receive("[" + (calls + streams).joined(separator: ",") + "]")
    XCTAssertEqual(handler.calls.count + handler.streams.count, ChannelPeer.maxOpenRequests)
    XCTAssertTrue(connection.sent.isEmpty)
    connection.receive(#"[{"id":100000,"stream":"slow"},{"id":100001,"path":"slow"}]"#)
    XCTAssertEqual(connection.sent.map { $0["error"]?.string }, ["too many requests", "too many requests"])
    // Calls without an id are never open, so they still go through
    connection.receive(#"{"path":"notify"}"#)
    XCTAssertEqual(handler.calls.count, half + 1)
    // Ending one makes room for one
    handler.streams[0].finish()
    connection.receive(#"{"id":100002,"stream":"slow"}"#)
    XCTAssertEqual(handler.streams.count, ChannelPeer.maxOpenRequests - half + 1)
    XCTAssertFalse(peer.isClosed)
  }
}
