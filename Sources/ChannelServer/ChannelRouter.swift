import Foundation

/// A channel server: routes incoming posts, streams and subscriptions by path, and publishes to topics. Everything
/// runs on the queue passed to `listen`.
public final class ChannelRouter: ChannelHandler {
  public enum Kind: String, Sendable {
    case post, stream, sub
  }
  public typealias PostHandler = (IncomingCall) throws -> Void
  public typealias StreamHandler = (IncomingStream) throws -> Void
  public typealias SubHandler = (IncomingSubscription) throws -> (topic: String?, body: JSON?)

  private var posts: [String: PostHandler] = [:]
  private var streams: [String: StreamHandler] = [:]
  private var subs: [String: SubHandler] = [:]
  private var otherPost: PostHandler?
  private var otherStream: StreamHandler?
  /// Every connected peer
  public private(set) var peers: [ObjectIdentifier: ChannelPeer] = [:]
  private var transports: [ChannelTransport] = []

  /// Runs before the handler of every post, stream start and sub that has one (like channel TS middleware, after
  /// the `api not found` check). Throwing answers with the error.
  public var check: ((Kind, String, ChannelPeer, JSON) throws -> Void)?
  public var onConnect: ((ChannelPeer) -> Void)?
  public var onDisconnect: ((ChannelPeer) -> Void)?

  public init() {}

  // MARK: Routes

  /// A post answered with the handler's result (`nil` for a void result)
  @discardableResult
  public func post(_ path: String, _ handler: @escaping (IncomingCall) throws -> JSON?) -> Self {
    posts[path] = { call in call.respond(try handler(call)) }
    return self
  }
  /// A post whose handler answers the call itself, later if it wants
  @discardableResult
  public func post(_ path: String, answering handler: @escaping PostHandler) -> Self {
    posts[path] = handler
    return self
  }
  /// Posts to paths without a route of their own
  @discardableResult
  public func postOther(_ handler: @escaping PostHandler) -> Self {
    otherPost = handler
    return self
  }
  @discardableResult
  public func stream(_ path: String, _ handler: @escaping StreamHandler) -> Self {
    streams[path] = handler
    return self
  }
  @discardableResult
  public func streamOther(_ handler: @escaping StreamHandler) -> Self {
    otherStream = handler
    return self
  }
  /// A subscription: the handler returns the topic to join (`nil` for one-shot) and the snapshot
  @discardableResult
  public func sub(_ path: String, _ handler: @escaping SubHandler) -> Self {
    subs[path] = handler
    return self
  }
  /// Paths with a post or stream route
  public var routes: Set<String> { Set(posts.keys).union(streams.keys) }

  /// Sends the event to every peer subscribed to the topic. `nil` isn't sent.
  public func publish(_ topic: String, _ body: JSON?) {
    guard let body else { return }
    for peer in peers.values { peer.publish(topic, body) }
  }

  // MARK: Serving

  /// Serves on a transport. `state` makes the connection's state from its upgrade request; throwing refuses it.
  public func listen(
    _ transport: ChannelTransport,
    queue: DispatchQueue,
    state: @escaping (UpgradeRequest) throws -> AnyObject? = { _ in nil },
    ready: @escaping (Result<UInt16, Error>) -> Void = { _ in }
  ) {
    transports.append(transport)
    transport.start(queue: queue, accept: { [weak self] request in
      let value = try state(request)
      return { connection in
        guard let self else {
          connection.close()
          return
        }
        let peer = ChannelPeer(connection: connection, handler: self)
        peer.state = value
        self.peers[ObjectIdentifier(peer)] = peer
        self.onConnect?(peer)
      }
    }, ready: ready)
  }

  /// Stops every transport, which closes every connection
  public func stop() {
    let transports = self.transports
    self.transports = []
    for transport in transports { transport.stop() }
  }

  // MARK: ChannelHandler

  public func peer(_ peer: ChannelPeer, post call: IncomingCall) {
    guard let handler = posts[call.path] ?? otherPost else { return call.fail(.apiNotFound) }
    do {
      try check?(.post, call.path, peer, call.context)
      try handler(call)
    } catch {
      call.fail(ChannelFailure(error))
    }
  }

  public func peer(_ peer: ChannelPeer, stream call: IncomingStream) {
    guard let handler = streams[call.path] ?? otherStream else { return call.fail(.apiNotFound) }
    do {
      try check?(.stream, call.path, peer, call.context)
      try handler(call)
    } catch {
      call.fail(ChannelFailure(error))
    }
  }

  public func peer(_ peer: ChannelPeer, subscribe call: IncomingSubscription) {
    guard let handler = subs[call.path] else { return call.fail(.subscriptionNotFound) }
    do {
      try check?(.sub, call.path, peer, call.context)
      let result = try handler(call)
      call.accept(topic: result.topic, body: result.body)
    } catch {
      call.fail(ChannelFailure(error))
    }
  }

  public func peerDisconnected(_ peer: ChannelPeer) {
    peers[ObjectIdentifier(peer)] = nil
    onDisconnect?(peer)
  }
}
