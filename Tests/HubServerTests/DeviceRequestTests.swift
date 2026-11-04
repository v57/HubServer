import Foundation
import XCTest
@testable import HubServer

/// `names` in Docs/Devices/vectors.json, which hub-server is held to as well
final class NameVectorTests: XCTestCase {
  let names = try! JSON.parse(Data(contentsOf: Bundle.module.url(forResource: "device-vectors", withExtension: "json", subdirectory: "Fixtures")!))["names"]!

  func testNormalized() {
    for vector in names["normalized"]!.array! {
      XCTAssertEqual(normalizeName(vector["input"]!.string!), vector["normalized"]!.string, vector["input"]!.string!)
    }
  }
  func testTheSameNameAndNot() {
    for group in names["same"]!.array! {
      XCTAssertEqual(Set(group.strings!.map(normalizeName)).count, 1, "\(group.strings!)")
    }
    for pair in names["different"]!.array! {
      XCTAssertNotEqual(normalizeName(pair.strings![0]), normalizeName(pair.strings![1]), "\(pair.strings!)")
    }
  }
  func testEveryLookalike() {
    for entry in names["lookalikes"]!.array! {
      let letter = entry["letter"]!.string!
      for other in entry["others"]!.string!.unicodeScalars {
        XCTAssertEqual(normalizeName("q\(other)q"), normalizeName("q\(letter)q"), "\(other) as \(letter)")
      }
    }
  }
  func testClean() {
    for vector in names["clean"]!.array! {
      XCTAssertEqual(Array(cleanName(vector["input"]!.string!).unicodeScalars), Array(vector["clean"]!.string!.unicodeScalars), vector["input"]!.string!)
    }
  }
  func testUnique() {
    for vector in names["unique"]!.array! {
      let taken = Set(vector["held"]!.strings!.map(normalizeName))
      let name = freeName(vector["asked"]!.string!) { taken.contains($0) }
      XCTAssertEqual(Array(name.unicodeScalars), Array(vector["name"]!.string!.unicodeScalars), vector["asked"]!.string!)
    }
  }
}

final class RequestGateTests: XCTestCase {
  private let queue = DispatchQueue(label: "gate-tests")

  private func request() -> WaitingRequest {
    let key = HubKeyPair().publicKey
    let certificate = Certificate(device: key, deviceId: HubCrypto.deviceId(spki: key), service: "service", instance: "test", iat: 0, exp: 0)
    return WaitingRequest(certificate: certificate, connection: HubConnection(key: nil, ip: nil))
  }

  func testAFloodFromOneSourceDoesNotPushOthersOut() {
    let gate = RequestGate(queue: queue)
    gate.interval = 0.02
    var admitted: [String] = []
    gate.admit = { admitted.append($0.deviceId) }
    let first = request(), flood = (0..<3).map { _ in request() }, other = request()
    queue.sync {
      gate.ask("attacker", first)
      XCTAssertEqual(admitted, [first.deviceId], "an idle hub admits at once")
      for request in flood { gate.ask("attacker", request) }
      gate.ask("someone", other)
      XCTAssertEqual(admitted.count, 1, "later turns wait")
    }
    Thread.sleep(forTimeInterval: 0.3)
    queue.sync {
      XCTAssertEqual(admitted, [first, flood[0], other, flood[1], flood[2]].map(\.deviceId), "the other source goes before the rest of the flood")
    }
  }

  func testRequestsAreLimitedAcrossSources() {
    queue.sync {
      let gate = RequestGate(queue: queue)
      gate.interval = 3600
      var admitted = 0
      gate.admit = { _ in admitted += 1 }
      for index in 0..<50 { gate.ask("10.0.0.\(index)", request()) }
      XCTAssertEqual(admitted, 1)
    }
  }

  func testWhatWaitsIsBounded() {
    queue.sync {
      let gate = RequestGate(queue: queue)
      gate.interval = 3600
      gate.admit = { _ in }
      gate.ask("first", request())
      let waiting = (0..<9).map { _ in request() }
      for request in waiting { gate.ask("same", request) }
      XCTAssertTrue(gate.has(waiting[7].deviceId))
      XCTAssertFalse(gate.has(waiting[8].deviceId), "8 per source")
      for index in 0..<4096 { gate.ask("10.\(index)", request()) }
      let late = request()
      gate.ask("one more", late)
      XCTAssertFalse(gate.has(late.deviceId), "4096 sources")
    }
  }

  func testARequestAskedTwiceWaitsOnce() {
    let gate = RequestGate(queue: queue)
    gate.interval = 0.02
    var admitted = 0
    gate.admit = { _ in admitted += 1 }
    queue.sync {
      gate.ask("first", request())
      let twice = request()
      gate.ask("a", twice)
      gate.ask("b", twice)
    }
    Thread.sleep(forTimeInterval: 0.2)
    queue.sync { XCTAssertEqual(admitted, 2) }
  }

  func testSources() {
    XCTAssertEqual(requestSource(nil), "unknown")
    XCTAssertEqual(requestSource("1.2.3.4"), "1.2.3.4")
    XCTAssertEqual(requestSource("::ffff:1.2.3.4"), "1.2.3.4")
    XCTAssertEqual(requestSource("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64")
    XCTAssertEqual(requestSource("2001:DB8:1:2::9"), "2001:db8:1:2::/64")
    XCTAssertEqual(requestSource("fe80::1%en0"), "fe80:0:0:0::/64")
  }
}

final class DeviceStoreTests: XCTestCase {
  private let queue = DispatchQueue(label: "store-tests")
  private let hubKey = HubKeyPair().publicKey
  private var storages: [Storage] = []
  /// A store's debounced save reads its registry, so they stay until the test has flushed
  private var registries: [DeviceRegistry] = []

  override func tearDown() {
    queue.sync { for storage in storages { storage.flush() } }
    registries = []
  }

  private func storage(_ directory: URL) -> Storage {
    let storage = Storage(directory: directory, queue: queue, log: { _ in })
    storages.append(storage)
    return storage
  }

  private func registry(_ devices: [(id: String, json: JSON)], in directory: URL) throws -> DeviceRegistry {
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let data: JSON = ["schema": 1, "devices": .object(JSONObject(devices.map { ($0.id, $0.json) })), "services": [:], "revokedKeys": []]
    try data.prettyText.write(to: directory.appendingPathComponent("devices.json"), atomically: true, encoding: .utf8)
    let registry = DeviceRegistry(storage: storage(directory), hubKey: hubKey)
    registries.append(registry)
    queue.sync { registry.load() }
    return registry
  }

  private func stored(_ name: String, approved: Bool = true, byOwner: Bool = false, at: String) -> JSON {
    var object: JSONObject = ["key": .string(HubKeyPair().publicKey), "name": .string(name), "approved": .bool(approved), "createdAt": .string(at), "lastSeen": .string(at)]
    if byOwner { object["nameByOwner"] = true }
    return .object(object)
  }

  private func temporary() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString) }

  func testOfDuplicatesTheLaterOneIsRenamedAndOwnerSetNamesStay() throws {
    let directory = temporary()
    let registry = try registry([
      ("later", stored("Alex", at: "2026-02-01T00:00:00.000Z")),
      ("first", stored("alex", at: "2026-01-01T00:00:00.000Z")),
      ("owner-a", stored("Mac", byOwner: true, at: "2026-03-01T00:00:00.000Z")),
      ("owner-b", stored("MAC", byOwner: true, at: "2026-03-02T00:00:00.000Z")),
      ("asks-mac", stored("M\u{0430}c", at: "2026-01-02T00:00:00.000Z")),
      ("pending", stored("Alex", approved: false, at: "2026-04-01T00:00:00.000Z")),
    ], in: directory)
    XCTAssertEqual(registry.device("first")?.name, "alex")
    XCTAssertEqual(registry.device("later")?.name, "Alex-2")
    XCTAssertEqual(registry.device("later")?.askedName, "Alex")
    XCTAssertEqual(registry.device("owner-a")?.name, "Mac")
    XCTAssertEqual(registry.device("owner-b")?.name, "MAC")
    XCTAssertEqual(registry.device("asks-mac")?.name, "M\u{0430}c-2")
    XCTAssertEqual(registry.device("pending")?.name, "Alex", "a request holds no name")
    // It's written at once
    storages.last?.waitForWrites()
    let written = try JSON.parse(Data(contentsOf: directory.appendingPathComponent("devices.json")))
    XCTAssertEqual(written["devices"]?["later"]?["name"]?.string, "Alex-2")
  }

  func testEveryDeviceGetsAValueItKeeps() throws {
    let directory = temporary()
    let registry = try registry([("old", stored("Old", at: "2026-01-01T00:00:00.000Z"))], in: directory)
    let value = try XCTUnwrap(registry.device("old")?.codeValue)
    storages.last?.waitForWrites()
    let again = DeviceRegistry(storage: storage(directory), hubKey: hubKey)
    registries.append(again)
    queue.sync { again.load() }
    XCTAssertEqual(again.device("old")?.codeValue, value)
  }

  func testAStoreWithTooManyRequestsKeepsTheNewest() throws {
    let rows = (0..<300).map { index in
      ("pending-\(index)", stored("P\(index)", approved: false, at: String(format: "2026-01-01T00:%02d:%02d.000Z", index / 60, index % 60)))
    }
    let registry = try registry(rows.map { (id: $0.0, json: $0.1) }, in: temporary())
    XCTAssertEqual(registry.pendingIds().count, maxPendingDevices)
    XCTAssertNil(registry.device("pending-0"))
    XCTAssertNotNil(registry.device("pending-299"))
  }

  func testAnOwnerNameMovesADeviceThatOnlyAskedAndRefusesAnOwnerSetOne() throws {
    let registry = try registry([
      ("asked", stored("Alex", at: "2026-01-01T00:00:00.000Z")),
      ("set", stored("Sam", byOwner: true, at: "2026-01-02T00:00:00.000Z")),
      ("other", stored("Other", at: "2026-01-03T00:00:00.000Z")),
    ], in: temporary())
    try queue.sync {
      try registry.rename("other", "Alex")
      XCTAssertEqual(registry.device("other")?.name, "Alex")
      XCTAssertEqual(registry.device("asked")?.name, "Alex-2")
      XCTAssertThrowsError(try registry.rename("other", "SAM")) { XCTAssertEqual(($0 as? ChannelFailure)?.message, "name taken") }
      try registry.update("set", name: "Other", os: nil, arch: nil, capabilities: nil)
      XCTAssertEqual(registry.device("set")?.name, "Sam", "a device's own suggestion never changes an owner's name")
    }
  }

  /// The attack: keys ground offline against a value the attacker assumed. The code used to cover only the key, so a
  /// ground key's code was known before it reached the hub.
  func testGrindingKeysAgainstAFixedValueNoLongerPredictsTheCode() throws {
    let fixed = HubCrypto.newCodeValue()
    func offline(_ key: String) -> String { HubCrypto.safetyCode(hubKey: hubKey, key: key, codeValue: fixed) }
    var seen: [String: HubKeyPair] = [:]
    var twins: (HubKeyPair, HubKeyPair)?
    while twins == nil {
      let key = HubKeyPair()
      if let twin = seen[offline(key.publicKey)] { twins = (twin, key) }
      seen[offline(key.publicKey)] = key
    }
    let (a, b) = try XCTUnwrap(twins)
    XCTAssertEqual(offline(a.publicKey), offline(b.publicKey), "offline the two share a code")
    let registry = try registry([], in: temporary())
    func request(_ key: HubKeyPair) -> JSON? {
      let certificate = Certificate(device: key.publicKey, deviceId: HubCrypto.deviceId(spki: key.publicKey), service: "s", instance: "test", deviceName: "Twin", iat: 0, exp: 0)
      _ = queue.sync { registry.seen(certificate, approve: false) }
      return queue.sync { registry.pending.array?.first { $0["key"]?.string == key.publicKey } }
    }
    let first = try XCTUnwrap(request(a)), second = try XCTUnwrap(request(b))
    XCTAssertNotEqual(first["codeValue"]?.string, fixed)
    XCTAssertNotEqual(first["codeValue"]?.string, second["codeValue"]?.string)
    XCTAssertEqual(first["safetyCode"]?.string, HubCrypto.safetyCode(hubKey: hubKey, key: a.publicKey, codeValue: first["codeValue"]!.string!))
    XCTAssertEqual(second["safetyCode"]?.string, HubCrypto.safetyCode(hubKey: hubKey, key: b.publicKey, codeValue: second["codeValue"]!.string!))
    // One in a million each: a match here would mean the code doesn't cover the hub's value
    XCTAssertFalse(first["safetyCode"]?.string == offline(a.publicKey) && second["safetyCode"]?.string == offline(b.publicKey))
  }
}
