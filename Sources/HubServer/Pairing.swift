import ChannelServer
import Foundation

extension HubServer {
  /// A pairing code for the first owner (protocol.md section 12)
  public struct PairingCode: Sendable, Equatable {
    /// `K7Q-2MX`
    public var code: String
    public var expires: Date
  }
}
/// Nested in `HubServer`, since HubService has its own `PairingCode`
typealias PairingCode = HubServer.PairingCode

/// Pairing codes: 6 Crockford base32 symbols, valid for an hour and one success. Only `scrypt(code, salt)` is kept
/// in `pairing.json`; the plain code goes to `pairing-code` for the launcher, both 0600. The files match hub-server's,
/// and the hub re-reads `pairing.json` on every attempt, so a code made by the one-shot `--pair` works at once.
/// Everything runs on `queue`, so verifications run one at a time, each taking at least a second.
final class Pairing {
  static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
  static let length = 6
  static let lifetime = 3600
  static let maxAttempts = 10

  private struct Stored: Equatable {
    var salt: String
    var hash: String
    var expires: Int
    var attempts: Int
  }
  let queue = DispatchQueue(label: "HubServer.pairing")
  /// Shortest verification
  var minimumDuration: TimeInterval = 1
  private let jsonURL: URL
  private let codeURL: URL
  private let log: (String) -> Void

  init(directory: URL, log: @escaping (String) -> Void) {
    jsonURL = directory.appendingPathComponent("pairing.json")
    codeURL = directory.appendingPathComponent("pairing-code")
    self.log = log
  }

  private static var now: Int { Int(Date().timeIntervalSince1970) }

  private func read() -> Stored? {
    guard let data = FileManager.default.contents(atPath: jsonURL.path), let json = try? JSON.parse(data),
      let salt = json["salt"]?.string, let hash = json["hash"]?.string, let expires = json["expires"]?.double,
      case .int(let attempts) = json["attempts"] ?? .null
    else { return nil }
    return Stored(salt: salt, hash: hash, expires: Int(expires), attempts: attempts)
  }

  private func isActive(_ stored: Stored?) -> Bool {
    guard let stored else { return false }
    return stored.expires > Pairing.now && stored.attempts < Pairing.maxAttempts
  }

  /// The code in use, when the plain one is stored and matches its hash
  var current: PairingCode? {
    let stored = read()
    guard isActive(stored), let stored, let text = try? String(contentsOf: codeURL, encoding: .utf8),
      let code = Pairing.normalize(text), let salt = Data(base64Encoded: stored.salt),
      Data(hash(code, salt: Array(salt))).base64EncodedString() == stored.hash
    else { return nil }
    return PairingCode(code: Pairing.format(code), expires: Date(timeIntervalSince1970: TimeInterval(stored.expires)))
  }

  /// The code in use as `pairing-code` has it, without checking it against the hash. Any queue.
  var displayed: PairingCode? {
    let stored = read()
    guard isActive(stored), let stored, let text = try? String(contentsOf: codeURL, encoding: .utf8),
      let code = Pairing.normalize(text)
    else { return nil }
    return PairingCode(code: Pairing.format(code), expires: Date(timeIntervalSince1970: TimeInterval(stored.expires)))
  }

  /// At start: a new code when `force`, else when `needed` (no owners) and no valid one is stored
  func start(needed: Bool, force: Bool = false) -> PairingCode? {
    if !force {
      guard needed else { return nil }
      if let current { return current }
    }
    return create()
  }

  /// A new code replacing the old one
  func create() -> PairingCode {
    let code = String(HubCrypto.randomBytes(Pairing.length).map { Pairing.alphabet[Int($0) % 32] })
    let salt = HubCrypto.randomBytes(16)
    let stored = Stored(salt: Data(salt).base64EncodedString(), hash: Data(hash(code, salt: salt)).base64EncodedString(),
      expires: Pairing.now + Pairing.lifetime, attempts: 0)
    write(stored)
    do {
      try atomicWrite(Data(Pairing.format(code).utf8), to: codeURL, mode: 0o600)
    } catch {
      log("Failed to write pairing-code: \(error)")
    }
    return PairingCode(code: Pairing.format(code), expires: Date(timeIntervalSince1970: TimeInterval(stored.expires)))
  }

  /// Checks a code, taking at least `minimumDuration`. A success consumes it. Call on `queue`.
  func verify(_ input: JSON?) -> Result<Void, ChannelFailure> {
    let started = Date()
    let result = check(input)
    let remaining = minimumDuration - Date().timeIntervalSince(started)
    if remaining > 0 { Thread.sleep(forTimeInterval: remaining) }
    return result
  }

  private func check(_ input: JSON?) -> Result<Void, ChannelFailure> {
    let stored = read()
    guard isActive(stored), var stored, let salt = Data(base64Encoded: stored.salt) else {
      if stored != nil { clear() }
      return .failure(ChannelFailure("no pairing code"))
    }
    let code = input?.string.flatMap(Pairing.normalize)
    // Hashes malformed input too, so every answer takes the same time
    let hash = Data(hash(code ?? "", salt: Array(salt))).base64EncodedString()
    // `--pair` replaced the code meanwhile: leave its files alone
    guard read() == stored else { return .failure(ChannelFailure("invalid pairing code")) }
    if code != nil, constantTimeEqual(Array(hash.utf8), Array(stored.hash.utf8)) {
      clear()
      return .success(())
    }
    stored.attempts += 1
    if stored.attempts >= Pairing.maxAttempts {
      log("Pairing code invalidated after \(Pairing.maxAttempts) wrong codes")
      clear()
    } else {
      write(stored)
    }
    return .failure(ChannelFailure("invalid pairing code"))
  }

  /// Ignores case, spaces and `-`; nil unless 6 symbols of the alphabet are left
  static func normalize(_ text: String) -> String? {
    let code = String(text.filter { !$0.isWhitespace && $0 != "-" }.uppercased())
    guard code.count == length, code.allSatisfy(alphabet.contains) else { return nil }
    return code
  }
  /// `K7Q2MX` → `K7Q-2MX`
  static func format(_ code: String) -> String {
    "\(code.prefix(3))-\(code.dropFirst(3))"
  }
  /// scrypt with N=16384, r=8, p=1 and 32 bytes, like hub-server
  static func hash(_ code: String, salt: [UInt8], n: Int = 16384) -> [UInt8] {
    Scrypt.derive(password: Array(code.utf8), salt: salt, n: n, length: 32)
  }
  /// scrypt's N, lower in tests
  var cost = 16384
  private func hash(_ code: String, salt: [UInt8]) -> [UInt8] {
    Pairing.hash(code, salt: salt, n: cost)
  }

  /// Deletes the files of an expired or used up code
  func clearIfExpired() {
    if let stored = read(), !isActive(stored) { clear() }
  }

  /// Forgets the code and deletes both files
  func clear() {
    unlink(jsonURL.path)
    unlink(codeURL.path)
  }

  private func write(_ stored: Stored) {
    let json: JSON = ["salt": .string(stored.salt), "hash": .string(stored.hash), "expires": .int(stored.expires), "attempts": .int(stored.attempts)]
    do {
      try atomicWrite(Data(json.text.utf8), to: jsonURL, mode: 0o600)
    } catch {
      log("Failed to write pairing.json: \(error)")
    }
  }

  private func constantTimeEqual(_ left: [UInt8], _ right: [UInt8]) -> Bool {
    guard left.count == right.count else { return false }
    var difference: UInt8 = 0
    for index in left.indices { difference |= left[index] ^ right[index] }
    return difference == 0
  }
}
