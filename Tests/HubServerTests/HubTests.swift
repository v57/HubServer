import Foundation
import XCTest
@testable import HubServer

/// Docs/Devices/vectors.json, copied to Fixtures/device-vectors.json
final class VectorTests: XCTestCase {
  var storages: [Storage] = []
  let vectors = try! JSON.parse(Data(contentsOf: Bundle.module.url(forResource: "device-vectors", withExtension: "json", subdirectory: "Fixtures")!))

  func testKeys() throws {
    for name in ["hub", "service", "device"] {
      let vector = vectors["keys"]![name]!
      let key = try HubKeyPair(fileText: vector["keyFile"]!.string!)
      XCTAssertEqual(key.publicKey, vector["publicKey"]!.string)
      XCTAssertEqual(key.fileText, vector["keyFile"]!.string)
      XCTAssertEqual(HubCrypto.hex(Array(key.privateKey.rawRepresentation)), vector["seed"]!.string)
    }
    let device = vectors["keys"]!["device"]!
    XCTAssertEqual(HubCrypto.deviceId(spki: device["publicKey"]!.string!), device["deviceId"]!.string)
    for vector in vectors["safetyCode"]!["cases"]!.array! {
      XCTAssertEqual(HubCrypto.safetyCode(hubKey: vector["hubKey"]!.string!, key: vector["deviceKey"]!.string!, codeValue: vector["codeValue"]!.string!), vector["code"]!.string)
    }
  }

  func testAuthTokens() throws {
    let hubKey = vectors["keys"]!["hub"]!["publicKey"]!.string!
    let expiry = vectors["auth"]!["expiry"]!.int!
    let security = try makeSecurity(hubKey: hubKey)
    let service = vectors["keys"]!["service"]!["publicKey"]!.string!
    try security.setMode(["requireV1": false])
    XCTAssertEqual(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "0", now: expiry - 60), service)
    // Expiry of a v0 token: 30 s of skew both ways, at most 300 s ahead
    XCTAssertNoThrow(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "0", now: expiry + 29))
    XCTAssertThrowsError(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "0", now: expiry + 30))
    XCTAssertNoThrow(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "0", now: expiry - 330))
    XCTAssertThrowsError(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "0", now: expiry - 331))
    try security.setMode(["requireV1": true])
    XCTAssertThrowsError(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "0", now: expiry - 60)) { error in
      XCTAssertEqual((error as? ChannelFailure)?.message, "unsupported version")
    }
    // A v0 token isn't a v1 one, and a v1 token needs a nonce of this hub's
    XCTAssertThrowsError(try security.verifyToken(vectors["auth"]!["v0"]!["header"]!.string, version: "1", now: expiry - 60))
    XCTAssertThrowsError(try security.verifyToken(vectors["auth"]!["v1"]!["header"]!.string, version: "1", now: expiry - 60)) { error in
      XCTAssertEqual((error as? ChannelFailure)?.message, "invalid nonce")
    }
    XCTAssertThrowsError(try security.verifyToken(vectors["auth"]!["v1"]!["header"]!.string, version: "2", now: expiry - 60)) { error in
      XCTAssertEqual((error as? ChannelFailure)?.message, "unsupported version")
    }
    XCTAssertNil(try security.verifyToken(nil, version: nil))
  }

  func testV1TokensSignANonceAndWorkOnce() throws {
    let hub = HubKeyPair(), other = HubKeyPair(), service = HubKeyPair()
    let security = try makeSecurity(hubKey: hub.publicKey)
    let now = Int(Date().timeIntervalSince1970)
    func token(_ nonce: String, hubKey: String? = nil, key: HubKeyPair? = nil, expiry: Int? = nil) -> String {
      let key = key ?? service, expiry = expiry ?? now + 30
      return "key.\(key.publicKey).\(key.sign("hub1:\(hubKey ?? hub.publicKey):\(nonce):\(expiry)")).\(expiry).\(nonce)"
    }
    let nonce = security.nonces.issue(now: now)
    XCTAssertEqual(try security.verifyToken(token(nonce), version: "1", now: now), service.publicKey)
    // Replayed, also with the nonce under another key
    XCTAssertThrowsError(try security.verifyToken(token(nonce), version: "1", now: now))
    XCTAssertThrowsError(try security.verifyToken(token(nonce, key: other), version: "1", now: now))
    // Signed for another hub: refused, and the nonce stays free
    let second = security.nonces.issue(now: now)
    XCTAssertThrowsError(try security.verifyToken(token(second, hubKey: other.publicKey), version: "1", now: now))
    let used = security.nonces.usedCount
    XCTAssertEqual(security.nonces.usedCount, used)
    XCTAssertNoThrow(try security.verifyToken(token(second), version: "1", now: now))
    // Longer than a nonce lasts
    XCTAssertThrowsError(try security.verifyToken(token(security.nonces.issue(now: now), expiry: now + 300), version: "1", now: now))
    // After the nonce's own expiry
    let old = security.nonces.issue(now: now)
    XCTAssertThrowsError(try security.verifyToken(token(old, expiry: now + 90), version: "1", now: now + nonceLifetime))
    // Not this hub's
    XCTAssertThrowsError(try security.verifyToken(token(TokenNonces().issue(now: now)), version: "1", now: now))
    XCTAssertThrowsError(try security.verifyToken(token("a.b"), version: "1", now: now))
  }

  func testNoncesStayBounded() {
    let nonces = TokenNonces(limit: 4)
    let now = 1_800_000_000
    for _ in 0..<1000 { _ = nonces.issue(now: now) }
    XCTAssertEqual(nonces.usedCount, 0)
    let used = (0..<4).map { _ in nonces.issue(now: now) }
    for nonce in used { XCTAssertTrue(nonces.consume(nonce, now: now)) }
    let waiting = nonces.issue(now: now)
    // A full store changes the secret: nothing can come back
    XCTAssertFalse(nonces.consume(nonces.issue(now: now), now: now))
    XCTAssertEqual(nonces.usedCount, 0)
    for nonce in used {
      XCTAssertFalse(nonces.isValid(nonce, now: now))
      XCTAssertFalse(nonces.consume(nonce, now: now))
    }
    XCTAssertFalse(nonces.isValid(waiting, now: now))
    XCTAssertTrue(nonces.consume(nonces.issue(now: now), now: now))
    // Expired entries make room without changing the secret
    let later = TokenNonces(limit: 2)
    let a = later.issue(now: now), b = later.issue(now: now)
    XCTAssertTrue(later.consume(a, now: now))
    XCTAssertTrue(later.consume(b, now: now))
    let next = now + nonceLifetime + 1
    XCTAssertTrue(later.consume(later.issue(now: next), now: next))
    XCTAssertEqual(later.usedCount, 1)
  }

  func testStoredRequireV1FalseFromBeforeAuthV2CountsAsUnset() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory.appendingPathComponent("data"), withIntermediateDirectories: true)
    let storage = Storage(directory: directory, queue: DispatchQueue(label: "test"), log: { _ in })
    storages.append(storage)
    try Data(#"{"security":{"mode":"default-allow","requireV1":false}}"#.utf8).write(to: storage.store("hub.json").url)
    let security = Security(storage: storage, hubKey: HubKeyPair().publicKey)
    security.load(hubKeyExisted: true)
    XCTAssertTrue(security.requireV1)
  }

  func testCertificates() throws {
    let hubKey = vectors["keys"]!["hub"]!["publicKey"]!.string!
    let service = vectors["keys"]!["service"]!["publicKey"]!.string!
    for name in ["certificate", "childCertificate"] {
      let vector = vectors[name]!
      let json = try JSON.parse(vector["json"]!.string!)
      XCTAssertEqual(HubCrypto.base64URLEncode(Data(vector["json"]!.string!.utf8)), vector["payload"]!.string)
      let now = json["iat"]!.int! + 10
      guard case .valid(let certificate) = verifyCertificate(vector["header"]!.string!, serviceKey: service, hubKey: hubKey, now: now) else {
        return XCTFail("\(name) didn't verify")
      }
      XCTAssertEqual(certificate.deviceId, vectors["keys"]!["device"]!["deviceId"]!.string)
      XCTAssertEqual(certificate.instance, json["instance"]!.string)
      XCTAssertEqual(certificate.parent, json["parent"]?.string)
      // Another service key, an expired one, or a changed payload is a plain key connection
      guard case .invalid = verifyCertificate(vector["header"]!.string!, serviceKey: hubKey, hubKey: hubKey, now: now),
        case .invalid = verifyCertificate(vector["header"]!.string!, serviceKey: service, hubKey: hubKey, now: json["exp"]!.int! + 31),
        case .invalid = verifyCertificate("x" + vector["header"]!.string!, serviceKey: service, hubKey: hubKey, now: now)
      else { return XCTFail("\(name) verified where it shouldn't") }
    }
  }

  func testCallerContext() throws {
    let caller = Caller(key: vectors["keys"]!["service"]!["publicKey"]!.string, device: (id: "8cef065b7af83669150b7d32704d3d3e", name: "Mac Studio"),
      groups: ["owners"], owner: true)
    let context: JSON = ["hub": ["caller": caller.json, "hubKey": vectors["keys"]!["hub"]!["publicKey"]!]]
    XCTAssertEqual(context.text, vectors["caller"]!["context"]!.text)
  }

  private func makeSecurity(hubKey: String) throws -> Security {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let storage = Storage(directory: directory, queue: DispatchQueue(label: "test"), log: { _ in })
    storages.append(storage)
    let security = Security(storage: storage, hubKey: hubKey)
    security.load(hubKeyExisted: false)
    return security
  }
}

final class SecurityTests: XCTestCase {
  func testScrypt() {
    // RFC 7914 section 12
    XCTAssertEqual(HubCrypto.hex(Scrypt.derive(password: [], salt: [], n: 16, r: 1, p: 1, length: 64)),
      "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
    XCTAssertEqual(HubCrypto.hex(Scrypt.derive(password: Array("password".utf8), salt: Array("NaCl".utf8), n: 1024, r: 8, p: 16, length: 64)),
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640")
    // The pairing hash, as node's scryptSync computes it
    XCTAssertEqual(Data(Pairing.hash("K7Q2MX", salt: Array(0..<16))).base64EncodedString(), "vpKsaQLDnWGQIvIlkpqo0Ds6DTE3jbZrBOMglsYpemQ=")
  }

  func testBuiltinAccess() {
    XCTAssertEqual(builtinAccess("hub/info"), .open)
    XCTAssertEqual(builtinAccess("hub/pair"), .auth)
    XCTAssertEqual(builtinAccess("hub/profile/update"), .auth)
    XCTAssertEqual(builtinAccess("hub/device/request"), .auth)
    XCTAssertEqual(builtinAccess("hub/api/services"), .auth)
    XCTAssertEqual(builtinAccess("hub/device/data"), .reporter)
    XCTAssertEqual(builtinAccess("hub/devices"), .grant)
    XCTAssertEqual(builtinAccess("hub/connections"), .owner)
    XCTAssertEqual(builtinAccess("hub/pair/new"), .owner)
    XCTAssertEqual(builtinAccess("hub/anything/new"), .owner)
    XCTAssertEqual(builtinAccess("network/agents/list"), .own)
    XCTAssertNil(builtinAccess("hubs/x"))
    XCTAssertNil(builtinAccess("s3/read"))
  }

  func testCallsByMode() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let storage = Storage(directory: directory, queue: DispatchQueue(label: "test"), log: { _ in })
    defer { withExtendedLifetime(storage) {} }
    let security = Security(storage: storage, hubKey: "hub")
    security.load(hubKeyExisted: false)
    XCTAssertEqual(security.mode, .defaultDeny)
    security.addOwner("owner")
    security.members.add(keyMember("reader"), to: "Readers")
    let owner = security.caller(Principal(key: "owner"))
    let reader = security.caller(Principal(key: "reader"))
    let stranger = security.caller(Principal(key: "stranger"))
    let anonymous = security.caller(Principal())
    XCTAssertTrue(owner.owner)
    XCTAssertEqual(reader.groups, ["Readers"])
    XCTAssertTrue(security.allowsCall(owner, "s3/read", isPublic: false))
    XCTAssertFalse(security.allowsCall(stranger, "s3/read", isPublic: false))
    XCTAssertTrue(security.allowsCall(anonymous, "s3/read", isPublic: true))
    security.grants.add(.group("Readers"), .prefix("s3/"), by: "owner")
    XCTAssertTrue(security.allowsCall(reader, "s3/read", isPublic: false))
    XCTAssertFalse(security.allowsCall(reader, "other/read", isPublic: false))
    XCTAssertThrowsError(try security.checkBuiltin(stranger, "hub/devices"))
    XCTAssertNoThrow(try security.checkBuiltin(security.caller(Principal(key: "x", device: "d")), "hub/devices"))
    XCTAssertThrowsError(try security.checkBuiltin(anonymous, "hub/api/services"))
    try security.setMode(["mode": "default-allow"])
    XCTAssertTrue(security.allowsCall(stranger, "s3/read", isPublic: false))
    security.names.add("s3/read", name: "S3: Read")
    XCTAssertFalse(security.allowsCall(stranger, "s3/read", isPublic: false))
    XCTAssertThrowsError(try security.setMode(["mode": "open"]))
    // Local mode: default-allow and the launcher key is an owner, neither stored
    security.local = true
    security.launcher = "launcher"
    XCTAssertTrue(security.caller(Principal(key: "launcher")).owner)
    XCTAssertFalse(security.members.has(keyMember("launcher"), in: ownersGroup))
  }

  func testPairing() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let pairing = Pairing(directory: directory, log: { _ in })
    pairing.minimumDuration = 0
    pairing.cost = 1024
    XCTAssertNil(pairing.start(needed: false))
    let code = try XCTUnwrap(pairing.start(needed: true))
    XCTAssertNotNil(code.code.range(of: "^[0-9A-HJKMNP-TV-Z]{3}-[0-9A-HJKMNP-TV-Z]{3}$", options: .regularExpression))
    // A stored code is used again at start
    XCTAssertEqual(pairing.start(needed: true), code)
    let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("pairing.json").path)
    XCTAssertEqual(attributes[.posixPermissions] as? Int, 0o600)
    XCTAssertEqual(Pairing.normalize(" k7q 2mx "), "K7Q2MX")
    XCTAssertNil(Pairing.normalize("K7Q-2MU"))
    XCTAssertThrowsError(try pairing.verify("nope").get())
    let wrong = (code.code.first == "A" ? "B" : "A") + code.code.dropFirst()
    guard case .failure(let failure) = pairing.verify(.string(wrong)) else { return XCTFail() }
    XCTAssertEqual(failure.message, "invalid pairing code")
    XCTAssertNoThrow(try pairing.verify(.string(code.code.lowercased().replacingOccurrences(of: "-", with: " "))).get())
    guard case .failure(let used) = pairing.verify(.string(code.code)) else { return XCTFail() }
    XCTAssertEqual(used.message, "no pairing code")
    XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("pairing-code").path))
    // Ten wrong codes invalidate one
    let next = pairing.create()
    for _ in 0..<10 { _ = pairing.verify("000000") }
    guard case .failure(let invalidated) = pairing.verify(.string(next.code)) else { return XCTFail() }
    XCTAssertEqual(invalidated.message, "no pairing code")
  }

  // MARK: A key the host keeps

  /// A store that remembers one key, as the keychain does
  private final class KeyStore {
    var data: Data?
    var failsLoading = false
    var dropsSaves = false
    var saves = 0
    func load() throws -> Data? {
      if failsLoading { throw HubServerError.invalidKeyFile }
      return data
    }
    func save(_ new: Data) {
      saves += 1
      if !dropsSaves { data = new }
    }
  }

  private func temporaryFile() throws -> URL {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    addTeardownBlock { try? FileManager.default.removeItem(at: folder) }
    return folder.appendingPathComponent("auth")
  }

  private func moved(_ file: URL, _ store: KeyStore) throws -> HubKeyPair {
    try HubKeyPair.moved(from: file, load: store.load, save: store.save)
  }

  func testAKeyFileMovesIntoTheStoreAndKeepsTheHubsIdentity() throws {
    let file = try temporaryFile()
    let old = try HubKeyPair.loadOrCreate(file)
    let store = KeyStore()
    XCTAssertEqual(try moved(file, store).publicKey, old.publicKey)
    XCTAssertEqual(store.data, old.privateKey.rawRepresentation)
    XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    // and the next start finds it there, without saving again
    XCTAssertEqual(try moved(file, store).publicKey, old.publicKey)
    XCTAssertEqual(store.saves, 1)
  }

  func testAFirstStartMakesOneKeyInTheStoreAndNoFile() throws {
    let file = try temporaryFile()
    let store = KeyStore()
    let key = try moved(file, store)
    XCTAssertEqual(store.data, key.privateKey.rawRepresentation)
    XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    XCTAssertEqual(try moved(file, store).publicKey, key.publicKey)
  }

  func testAStoreThatCantBeReadNeverGetsANewKey() throws {
    let file = try temporaryFile()
    let old = try HubKeyPair.loadOrCreate(file)
    let store = KeyStore()
    store.failsLoading = true
    XCTAssertThrowsError(try moved(file, store))
    XCTAssertEqual(store.saves, 0)
    XCTAssertEqual(try HubKeyPair.loadOrCreate(file).publicKey, old.publicKey)
  }

  func testTheFileStaysWhenTheStoreDidntKeepTheKey() throws {
    let file = try temporaryFile()
    let old = try HubKeyPair.loadOrCreate(file)
    let store = KeyStore()
    store.dropsSaves = true
    XCTAssertThrowsError(try moved(file, store))
    XCTAssertEqual(try HubKeyPair.loadOrCreate(file).publicKey, old.publicKey)
  }

  func testAFileLeftBesideTheSameKeyInTheStoreGoes() throws {
    let file = try temporaryFile()
    let old = try HubKeyPair.loadOrCreate(file)
    let store = KeyStore()
    store.data = old.privateKey.rawRepresentation
    XCTAssertEqual(try moved(file, store).publicKey, old.publicKey)
    XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    XCTAssertEqual(store.saves, 0)
  }

  func testAFileThatDiffersFromTheStoreWinsSinceItBelongsWithTheHubsData() throws {
    let file = try temporaryFile()
    let old = try HubKeyPair.loadOrCreate(file)
    let store = KeyStore()
    store.data = HubKeyPair().privateKey.rawRepresentation
    XCTAssertEqual(try moved(file, store).publicKey, old.publicKey)
    XCTAssertEqual(store.data, old.privateKey.rawRepresentation)
  }

  func testAHubWithAKeyFromItsHostWritesNoKeyFile() throws {
    let directory = try temporaryFile().deletingLastPathComponent()
    let key = HubKeyPair()
    var configuration = HubServer.Configuration(dataDirectory: directory)
    configuration.key = key
    let hub = try Hub(configuration: configuration, queue: DispatchQueue(label: "test"), log: { _ in })
    XCTAssertEqual(hub.hubKey, key.publicKey)
    XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("auth").path))
  }
}
