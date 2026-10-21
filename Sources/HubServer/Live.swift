import ChannelServer
import Foundation

/// What a hub stream shows. Streams of a topic recompute when it changes.
enum LiveTopic: Hashable {
  case status, badges, connections, devices, pending, deviceData(String), api, providers, security, grants, groups
  case hostPending, callPending, whitelist, header
  case network, networkGenerations, networkRevoked, netNode, netList

  /// Changes within this many seconds are sent together
  var delay: TimeInterval {
    switch self {
    case .connections, .netList: 0.5
    case .devices: 0.1
    default: 0.03
    }
  }
}

/// The hub's streams of current values (channel TS `LazyState`): a subscriber gets the current value at once, then
/// a new value after every change of its topic that changed what it sees. Every subscriber computes its own value,
/// since many depend on the caller. Confined to the hub's queue.
final class LiveValues {
  private final class Subscriber {
    let stream: IncomingStream
    let compute: () throws -> JSON
    var last: JSON?
    init(stream: IncomingStream, compute: @escaping () throws -> JSON) {
      self.stream = stream
      self.compute = compute
    }
  }
  private let queue: DispatchQueue
  private var subscribers: [LiveTopic: [ObjectIdentifier: Subscriber]] = [:]
  private var dirty = Set<LiveTopic>()
  private var scheduled = Set<LiveTopic>()

  init(queue: DispatchQueue) {
    self.queue = queue
  }

  /// Streams `compute` to the caller until it cancels. Throwing on the first value fails the stream.
  func stream(_ stream: IncomingStream, topic: LiveTopic, compute: @escaping () throws -> JSON) throws {
    let value = try compute()
    let subscriber = Subscriber(stream: stream, compute: compute)
    subscriber.last = value
    stream.send(value)
    let id = ObjectIdentifier(subscriber)
    subscribers[topic, default: [:]][id] = subscriber
    stream.onCancel { [weak self] in
      self?.subscribers[topic]?[id] = nil
      if self?.subscribers[topic]?.isEmpty == true { self?.subscribers[topic] = nil }
    }
  }

  /// The topic changed: its streams recompute soon
  func changed(_ topic: LiveTopic) {
    guard subscribers[topic] != nil, !scheduled.contains(topic) else { return }
    scheduled.insert(topic)
    queue.asyncAfter(deadline: .now() + topic.delay) { [weak self] in
      self?.scheduled.remove(topic)
      self?.send(topic)
    }
  }

  func changed(_ topics: LiveTopic...) {
    for topic in topics { changed(topic) }
  }

  /// Every per-device data stream
  func changedDeviceData() {
    for topic in subscribers.keys {
      if case .deviceData = topic { changed(topic) }
    }
  }

  private func send(_ topic: LiveTopic) {
    guard let subscribers = subscribers[topic] else { return }
    for subscriber in subscribers.values {
      guard let value = try? subscriber.compute(), value != subscriber.last else { continue }
      subscriber.last = value
      subscriber.stream.send(value)
    }
  }
}
