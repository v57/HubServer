import Foundation

/// An error reply (channel wire v2 §1): a message, an optional code (string or integer) and optional info
public struct ChannelFailure: Error, Sendable, Equatable, CustomStringConvertible, ExpressibleByStringLiteral {
  public var message: String
  public var code: JSON?
  public var info: JSON?
  public init(_ message: String, code: JSON? = nil, info: JSON? = nil) {
    self.message = message.isEmpty ? "error" : message
    self.code = code
    self.info = info
  }
  public init(stringLiteral value: String) {
    self.init(value)
  }
  /// A thrown error as a reply: a `ChannelFailure` as it is, anything else by its description
  public init(_ error: Error) {
    if let failure = error as? ChannelFailure {
      self = failure
    } else {
      self.init(String(describing: error))
    }
  }
  public var description: String { message }

  public static let apiNotFound = ChannelFailure("api not found", code: "not_found")
  public static let subscriptionNotFound = ChannelFailure("subscription not found", code: "not_found")
  public static let cancelled = ChannelFailure("cancelled", code: "cancelled")
  /// Local only: the connection closed before the answer came
  public static let disconnected = ChannelFailure("disconnected", code: "disconnected")

  /// `{ id, error, code?, info? }`
  func response(id: Int) -> JSON {
    var object: JSONObject = ["id": .int(id), "error": .string(message)]
    if let code, code.string != nil || code.int != nil { object["code"] = code }
    if let info { object["info"] = info }
    return .object(object)
  }
}

/// What a peer receives from the other side
public protocol ChannelHandler: AnyObject {
  func peer(_ peer: ChannelPeer, post call: IncomingCall)
  func peer(_ peer: ChannelPeer, stream call: IncomingStream)
  func peer(_ peer: ChannelPeer, subscribe call: IncomingSubscription)
  func peerDisconnected(_ peer: ChannelPeer)
}

/// An incoming post. Answer it once with `respond` or `fail`; later answers are ignored.
public final class IncomingCall {
  public let path: String
  /// Missing for fire-and-forget calls, which get no answer
  public let id: Int?
  public let body: JSON?
  /// The request's `context`, `{}` when missing
  public let context: JSON
  public unowned let peer: ChannelPeer
  public private(set) var isCancelled = false
  public private(set) var isFinished = false
  private var cancelActions: [() -> Void] = []

  init(path: String, id: Int?, body: JSON?, context: JSON, peer: ChannelPeer) {
    self.path = path
    self.id = id
    self.body = body
    self.context = context
    self.peer = peer
  }
  /// `nil` sends `{ id }` without a body (a void result)
  public func respond(_ body: JSON?) {
    guard finish() else { return }
    guard let id else { return }
    var object: JSONObject = ["id": .int(id)]
    if let body { object["body"] = body }
    peer.write(.object(object))
  }
  public func fail(_ failure: ChannelFailure) {
    guard finish() else { return }
    guard let id else { return }
    peer.write(failure.response(id: id))
  }
  public func finish(_ result: Result<JSON?, Error>) {
    switch result {
    case .success(let body): respond(body)
    case .failure(let error): fail(ChannelFailure(error))
    }
  }
  /// Runs when the caller cancels or disconnects before the answer. Runs at once when that already happened.
  public func onCancel(_ action: @escaping () -> Void) {
    if isCancelled {
      action()
    } else if !isFinished {
      cancelActions.append(action)
    }
  }
  private func finish() -> Bool {
    guard !isFinished else { return false }
    isFinished = true
    cancelActions = []
    if let id, peer.incomingCalls[id] === self { peer.incomingCalls[id] = nil }
    return true
  }
  /// `{cancel}` from the caller: answers `cancelled`. A disconnect answers nothing.
  func cancel(reply: Bool) {
    guard !isFinished else { return }
    isCancelled = true
    let actions = cancelActions
    if reply { fail(.cancelled) } else { _ = finish() }
    for action in actions { action() }
  }
}

/// An incoming stream: `send` values, then `finish` or `fail`
public final class IncomingStream {
  public let path: String
  public let id: Int
  public let body: JSON?
  public let context: JSON
  public unowned let peer: ChannelPeer
  public private(set) var isFinished = false
  private var cancelActions: [() -> Void] = []

  init(path: String, id: Int, body: JSON?, context: JSON, peer: ChannelPeer) {
    self.path = path
    self.id = id
    self.body = body
    self.context = context
    self.peer = peer
  }
  public func send(_ value: JSON?) {
    guard !isFinished else { return }
    var object: JSONObject = ["id": .int(id)]
    if let value { object["body"] = value }
    peer.write(.object(object))
  }
  public func finish() {
    guard end() else { return }
    peer.write(["id": .int(id), "done": true])
  }
  public func fail(_ failure: ChannelFailure) {
    guard end() else { return }
    peer.write(failure.response(id: id))
  }
  /// Runs when the caller cancels or disconnects. Runs at once when that already happened.
  public func onCancel(_ action: @escaping () -> Void) {
    if isFinished {
      if cancelled { action() }
    } else {
      cancelActions.append(action)
    }
  }
  private var cancelled = false
  private func end() -> Bool {
    guard !isFinished else { return false }
    isFinished = true
    cancelActions = []
    if peer.incomingStreams[id] === self { peer.incomingStreams[id] = nil }
    return true
  }
  func cancel() {
    guard !isFinished else { return }
    cancelled = true
    let actions = cancelActions
    _ = end()
    for action in actions { action() }
  }
}

/// An incoming `sub`. `accept` with a topic joins the peer to it; without one it is one-shot.
public final class IncomingSubscription {
  public let path: String
  public let id: Int?
  public let body: JSON?
  public let context: JSON
  public unowned let peer: ChannelPeer
  private var isFinished = false
  init(path: String, id: Int?, body: JSON?, context: JSON, peer: ChannelPeer) {
    self.path = path
    self.id = id
    self.body = body
    self.context = context
    self.peer = peer
  }
  public func accept(topic: String?, body: JSON?) {
    guard !isFinished else { return }
    isFinished = true
    if let topic { peer.topics.insert(topic) }
    guard let id else { return }
    var object: JSONObject = ["id": .int(id)]
    if let topic { object["topic"] = .string(topic) }
    if let body { object["body"] = body }
    peer.write(.object(object))
  }
  public func fail(_ failure: ChannelFailure) {
    guard !isFinished else { return }
    isFinished = true
    guard let id else { return }
    peer.write(failure.response(id: id))
  }
}

/// One side of a channel connection. Channel is symmetric: the peer answers the other side's posts, streams and
/// subscriptions through its handler, and sends its own posts and streams to the other side. Confined to the
/// transport's queue.
public final class ChannelPeer {
  /// What the other side of an outgoing stream sent
  public enum StreamEvent {
    case value(JSON?)
    case done
    case failure(ChannelFailure)
  }

  public let connection: MessageConnection
  public weak var handler: ChannelHandler?
  /// The connection's state, set by the server that accepted it
  public var state: AnyObject?
  /// Topics this peer subscribed to
  public internal(set) var topics = Set<String>()
  public private(set) var isClosed = false

  fileprivate(set) var incomingCalls: [Int: IncomingCall] = [:]
  fileprivate(set) var incomingStreams: [Int: IncomingStream] = [:]
  private var nextId = 0
  private var responses: [Int: (JSONObject) -> Bool] = [:]

  public init(connection: MessageConnection, handler: ChannelHandler?) {
    self.connection = connection
    self.handler = handler
    connection.onMessage = { [weak self] text in self?.receive(text) }
    connection.onClose = { [weak self] in self?.closed() }
  }

  // MARK: Outgoing

  /// Sends a post and calls `response` once with the answer, or with `disconnected` if the connection closes first.
  /// Returns the request id, for `cancel`.
  @discardableResult
  public func request(_ path: String, body: JSON? = nil, context: JSON? = nil, response: @escaping (Result<JSON?, ChannelFailure>) -> Void) -> Int {
    let id = makeId()
    guard !isClosed else {
      response(.failure(.disconnected))
      return id
    }
    responses[id] = { message in
      if let failure = ChannelPeer.failure(message) {
        response(.failure(failure))
      } else {
        response(.success(message["body"]))
      }
      return true
    }
    var object: JSONObject = ["id": .int(id), "path": .string(path)]
    if let body { object["body"] = body }
    if let context { object["context"] = context }
    write(.object(object))
    return id
  }

  /// Sends a post that gets no answer
  public func notify(_ path: String, body: JSON? = nil, context: JSON? = nil) {
    var object: JSONObject = ["path": .string(path)]
    if let body { object["body"] = body }
    if let context { object["context"] = context }
    write(.object(object))
  }

  /// Starts a stream. `event` gets every value, then `done` or a failure (`disconnected` if the connection closes).
  @discardableResult
  public func stream(_ path: String, body: JSON? = nil, context: JSON? = nil, event: @escaping (StreamEvent) -> Void) -> Int {
    let id = makeId()
    guard !isClosed else {
      event(.failure(.disconnected))
      return id
    }
    responses[id] = { message in
      if let failure = ChannelPeer.failure(message) {
        event(.failure(failure))
        return true
      } else if message["done"]?.bool == true {
        event(.done)
        return true
      } else {
        event(.value(message["body"]))
        return false
      }
    }
    var object: JSONObject = ["id": .int(id), "stream": .string(path)]
    if let body { object["body"] = body }
    if let context { object["context"] = context }
    write(.object(object))
    return id
  }

  /// Stops waiting for a post or stream and tells the other side with `{ cancel }`
  public func cancel(_ id: Int) {
    guard responses.removeValue(forKey: id) != nil else { return }
    write(["cancel": .int(id)])
  }

  /// Sends an event of a topic the peer subscribed to
  public func publish(_ topic: String, _ body: JSON) {
    guard topics.contains(topic) else { return }
    write(["topic": .string(topic), "body": body])
  }

  public func close() {
    connection.close()
  }

  func write(_ message: JSON) {
    guard !isClosed else { return }
    connection.send(message.text)
  }

  private func makeId() -> Int {
    defer { nextId += 1 }
    return nextId
  }

  private static func failure(_ message: JSONObject) -> ChannelFailure? {
    guard let error = message["error"], !error.isNull else { return nil }
    let text = error.string ?? error["message"]?.string ?? "error"
    return ChannelFailure(text, code: message["code"], info: message["info"])
  }

  // MARK: Incoming

  /// One text message: an object or an array of them. Text that isn't JSON closes the connection.
  public func receive(_ text: String) {
    guard !isClosed else { return }
    let message: JSON
    do {
      message = try JSON.parse(text)
    } catch {
      connection.close()
      return
    }
    if case .array(let messages) = message {
      for message in messages where !isClosed {
        if case .object(let object) = message { receiveOne(object) }
      }
    } else if case .object(let object) = message {
      receiveOne(object)
    }
  }

  private func receiveOne(_ message: JSONObject) {
    let id = message["id"]?.int
    let context = message["context"].flatMap { $0.isNull ? nil : $0 } ?? .object([:])
    if let path = message["path"]?.string, !path.isEmpty {
      let call = IncomingCall(path: path, id: id, body: message["body"], context: context, peer: self)
      if let id { incomingCalls[id] = call }
      guard let handler else { return call.fail(.apiNotFound) }
      handler.peer(self, post: call)
    } else if let path = message["stream"]?.string, !path.isEmpty {
      guard let id else { return }
      let stream = IncomingStream(path: path, id: id, body: message["body"], context: context, peer: self)
      incomingStreams[id] = stream
      guard let handler else { return stream.fail(.apiNotFound) }
      handler.peer(self, stream: stream)
    } else if let cancel = message["cancel"] {
      guard let id = cancel.int else { return }
      incomingStreams[id]?.cancel()
      incomingCalls[id]?.cancel(reply: true)
    } else if let path = message["sub"]?.string, !path.isEmpty {
      let subscription = IncomingSubscription(path: path, id: id, body: message["body"], context: context, peer: self)
      guard let handler else { return subscription.fail(.subscriptionNotFound) }
      handler.peer(self, subscribe: subscription)
    } else if let topic = message["unsub"]?.string, !topic.isEmpty {
      topics.remove(topic)
    } else if let topic = message["topic"]?.string, !topic.isEmpty {
      // Answers to subscriptions and events: this peer doesn't subscribe, so there is nothing to deliver
      if let id { _ = responses.removeValue(forKey: id) }
    } else if let id {
      guard let response = responses[id] else { return }
      if response(message) { responses[id] = nil }
    }
  }

  private func closed() {
    guard !isClosed else { return }
    isClosed = true
    let calls = incomingCalls.values
    let streams = incomingStreams.values
    incomingCalls = [:]
    incomingStreams = [:]
    for call in calls { call.cancel(reply: false) }
    for stream in streams { stream.cancel() }
    let pending = responses.sorted { $0.key < $1.key }
    responses = [:]
    for (_, response) in pending { _ = response(["error": "disconnected", "code": "disconnected"]) }
    topics = []
    handler?.peerDisconnected(self)
  }
}
