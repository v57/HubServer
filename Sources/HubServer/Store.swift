import Foundation

/// A JSON file in the data directory (protocol.md section 7). Writes are debounced, encoded on the hub's queue and
/// written atomically on a background queue, one at a time. A missing file loads as nothing. A file that can't be
/// read or decoded is moved aside to `<name>.corrupt-<unix time>` and `corrupt` is set, so the hub can deny what it
/// would have granted.
final class JSONStore {
  let url: URL
  let mode: mode_t
  private(set) var corrupt = false
  private unowned let storage: Storage
  private var isSavePending = false
  /// Encodes the current value, on the hub's queue
  var encode: () -> JSON = { .null }

  init(_ name: String, storage: Storage, mode: mode_t = 0o644) {
    self.url = storage.directory.appendingPathComponent(name)
    self.mode = mode
    self.storage = storage
  }

  var exists: Bool { FileManager.default.fileExists(atPath: url.path) }

  /// The stored value, nil when missing or corrupt. `decode` throwing also counts as corrupt.
  @discardableResult
  func load(_ decode: (JSON) throws -> Void) -> Bool {
    guard let data = FileManager.default.contents(atPath: url.path) else { return false }
    do {
      try decode(try JSON.parse(data))
      corrupt = false
      return true
    } catch {
      corrupt = true
      let aside = url.path + ".corrupt-\(Int(Date().timeIntervalSince1970))"
      storage.log("\(url.lastPathComponent) is corrupt, moved it to \(aside): \(error)")
      if rename(url.path, aside) != 0 { storage.log("Failed to move \(url.lastPathComponent) aside") }
      return false
    }
  }

  /// Writes soon, once for every change made until then
  func save() {
    guard !isSavePending else { return }
    isSavePending = true
    storage.queue.asyncAfter(deadline: .now() + storage.saveDelay) { [weak self] in
      guard let self, self.isSavePending else { return }
      self.writeNow()
    }
  }

  /// Encodes now and queues the write
  func writeNow() {
    isSavePending = false
    let data = Data(encode().prettyText.utf8)
    storage.write(data, to: url, mode: mode)
  }

  /// Writes now if a save is pending
  func flush() {
    if isSavePending { writeNow() }
  }
}

/// The data directory: where the stores live and the queue their writes go through
final class Storage {
  let directory: URL
  /// The hub's queue, where stores are encoded
  let queue: DispatchQueue
  let saveDelay: TimeInterval
  let log: (String) -> Void
  private let io = DispatchQueue(label: "HubServer.storage")
  private var stores: [JSONStore] = []

  init(directory: URL, queue: DispatchQueue, saveDelay: TimeInterval = 0.2, log: @escaping (String) -> Void) {
    self.directory = directory
    self.queue = queue
    self.saveDelay = saveDelay
    self.log = log
  }

  func store(_ name: String, mode: mode_t = 0o644) -> JSONStore {
    let store = JSONStore(name, storage: self, mode: mode)
    stores.append(store)
    return store
  }

  func url(_ name: String) -> URL { directory.appendingPathComponent(name) }

  func write(_ data: Data, to url: URL, mode: mode_t) {
    let log = self.log
    io.async {
      do {
        try atomicWrite(data, to: url, mode: mode)
      } catch {
        log("Failed to write \(url.lastPathComponent): \(error)")
      }
    }
  }

  func remove(_ url: URL) {
    io.async { unlink(url.path) }
  }

  /// Writes every pending store and waits for the writes, for stopping
  func flush() {
    for store in stores { store.flush() }
    io.sync {}
  }

  /// Waits for queued writes, from any queue but the io one
  func waitForWrites() {
    io.sync {}
  }
}
