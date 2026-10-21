import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// Encodings of protocol.md section 1

enum HubCrypto {
  /// Ed25519 SubjectPublicKeyInfo DER prefix, followed by the 32-byte key
  static let spkiPrefix: [UInt8] = [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]
  /// Ed25519 PKCS#8 DER prefix, followed by the 32-byte seed
  static let pkcs8Prefix: [UInt8] = [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]

  /// The Ed25519 key of an SPKI (base64), nil if it isn't one
  static func publicKey(spki: String) -> Curve25519.Signing.PublicKey? {
    guard let der = Data(base64Encoded: spki), der.count == 44, Array(der.prefix(12)) == spkiPrefix else { return nil }
    return try? Curve25519.Signing.PublicKey(rawRepresentation: der.suffix(32))
  }
  static func spki(_ key: Curve25519.Signing.PublicKey) -> String {
    Data(spkiPrefix + Array(key.rawRepresentation)).base64EncodedString()
  }
  /// Verifies a base64 signature over the UTF-8 bytes of `message`
  static func verify(signature: String, message: String, spki: String) -> Bool {
    guard let key = publicKey(spki: spki), let signature = Data(base64Encoded: signature) else { return false }
    return key.isValidSignature(signature, for: Data(message.utf8))
  }
  static func sha256(_ data: Data) -> [UInt8] {
    Array(SHA256.hash(data: data))
  }
  static func hex(_ bytes: [UInt8]) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var result = [UInt8]()
    result.reserveCapacity(bytes.count * 2)
    for byte in bytes {
      result.append(digits[Int(byte >> 4)])
      result.append(digits[Int(byte & 0x0F)])
    }
    return String(decoding: result, as: UTF8.self)
  }
  /// First 32 hex characters of SHA-256 of the SPKI DER bytes
  static func deviceId(spki: String) -> String {
    String(hex(sha256(Data(base64Encoded: spki) ?? Data())).prefix(32))
  }
  /// `ddd ddd` from the first 8 hex characters of SHA-256 of the SPKI DER bytes
  static func safetyCode(spki: String) -> String {
    let hash = sha256(Data(base64Encoded: spki) ?? Data())
    let value = UInt32(hash[0]) << 24 | UInt32(hash[1]) << 16 | UInt32(hash[2]) << 8 | UInt32(hash[3])
    let digits = String(value % 1_000_000)
    let code = String(repeating: "0", count: 6 - digits.count) + digits
    return "\(code.prefix(3)) \(code.suffix(3))"
  }
  static func base64URLDecode(_ text: String) -> Data? {
    guard text.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }) else { return nil }
    var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 { base64 += "=" }
    return Data(base64Encoded: base64)
  }
  static func base64URLEncode(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
  static func randomBytes(_ count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
  }
}

/// An Ed25519 key pair in the key file format: base64 of PKCS#8 DER (48 bytes) then SPKI DER (44 bytes)
public struct HubKeyPair: Sendable {
  public let privateKey: Curve25519.Signing.PrivateKey
  public var publicKey: String { HubCrypto.spki(privateKey.publicKey) }

  public init(privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey()) {
    self.privateKey = privateKey
  }
  /// Reads the key file text. The public key is derived from the private part.
  public init(fileText: String) throws {
    guard let der = Data(base64Encoded: fileText.trimmingCharacters(in: .whitespacesAndNewlines)), der.count >= 48,
      Array(der.prefix(16)) == HubCrypto.pkcs8Prefix
    else { throw HubServerError.invalidKeyFile }
    privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: der[der.startIndex + 16..<der.startIndex + 48])
  }
  public var fileText: String {
    Data(HubCrypto.pkcs8Prefix + Array(privateKey.rawRepresentation) + HubCrypto.spkiPrefix + Array(privateKey.publicKey.rawRepresentation))
      .base64EncodedString()
  }
  public func sign(_ message: String) -> String {
    sign(data: Data(message.utf8))
  }
  public func sign(data: Data) -> String {
    (try? privateKey.signature(for: data))?.base64EncodedString() ?? ""
  }
  /// Loads the key file, creating it (0600, atomically) when it doesn't exist
  public static func loadOrCreate(_ url: URL) throws -> HubKeyPair {
    if FileManager.default.fileExists(atPath: url.path) {
      return try HubKeyPair(fileText: String(contentsOf: url, encoding: .utf8))
    }
    let key = HubKeyPair()
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try atomicWrite(Data(key.fileText.utf8), to: url, mode: 0o600)
    return key
  }
}

public enum HubServerError: Error, CustomStringConvertible {
  case invalidKeyFile
  case notRunning
  case alreadyRunning
  case listen(String)
  public var description: String {
    switch self {
    case .invalidKeyFile: "invalid key file"
    case .notRunning: "the hub isn't running"
    case .alreadyRunning: "the hub is already running"
    case .listen(let reason): "listen failed: \(reason)"
    }
  }
}

/// Writes to a temporary file in the same directory and renames it over the target, so readers never see half a file
func atomicWrite(_ data: Data, to url: URL, mode: mode_t = 0o644) throws {
  let directory = url.deletingLastPathComponent()
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  let temporary = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
  let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL, mode)
  guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  var failed = false
  data.withUnsafeBytes { buffer in
    var offset = 0
    while offset < buffer.count {
      let written = write(descriptor, buffer.baseAddress! + offset, buffer.count - offset)
      if written <= 0 {
        failed = true
        return
      }
      offset += written
    }
  }
  if !failed { failed = fsync(descriptor) != 0 }
  close(descriptor)
  if failed || rename(temporary.path, url.path) != 0 {
    let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    unlink(temporary.path)
    throw error
  }
}

// MARK: - scrypt (RFC 7914), for pairing codes

// Raw pointers and `@_optimize(speed)`, so debug builds (tests, `swift run`) don't take seconds per hash
enum Scrypt {
  @_optimize(speed)
  static func derive(password: [UInt8], salt: [UInt8], n: Int = 16384, r: Int = 8, p: Int = 1, length: Int = 64) -> [UInt8] {
    let blockSize = 128 * r
    let words = 32 * r
    var b = pbkdf2(password: password, salt: salt, length: p * blockSize)
    let x = UnsafeMutablePointer<UInt32>.allocate(capacity: words)
    let y = UnsafeMutablePointer<UInt32>.allocate(capacity: words)
    let v = UnsafeMutablePointer<UInt32>.allocate(capacity: words * n)
    let t = UnsafeMutablePointer<UInt32>.allocate(capacity: 16)
    defer {
      x.deallocate()
      y.deallocate()
      v.deallocate()
      t.deallocate()
    }
    for i in 0..<p {
      let offset = i * blockSize
      for k in 0..<words {
        let j = offset + k * 4
        x[k] = UInt32(b[j]) | UInt32(b[j + 1]) << 8 | UInt32(b[j + 2]) << 16 | UInt32(b[j + 3]) << 24
      }
      for index in 0..<n {
        (v + index * words).update(from: x, count: words)
        blockMix(x, y, t, r)
      }
      let last = (2 * r - 1) * 16
      let mask = UInt32(n - 1)
      for _ in 0..<n {
        let row = v + Int(x[last] & mask) * words
        var k = 0
        while k < words {
          x[k] ^= row[k]
          k += 1
        }
        blockMix(x, y, t, r)
      }
      for k in 0..<words {
        let j = offset + k * 4
        b[j] = UInt8(x[k] & 0xFF)
        b[j + 1] = UInt8(x[k] >> 8 & 0xFF)
        b[j + 2] = UInt8(x[k] >> 16 & 0xFF)
        b[j + 3] = UInt8(x[k] >> 24 & 0xFF)
      }
    }
    return pbkdf2(password: password, salt: b, length: length)
  }

  /// PBKDF2-HMAC-SHA256 with one iteration, as scrypt uses it
  static func pbkdf2(password: [UInt8], salt: [UInt8], length: Int) -> [UInt8] {
    let key = SymmetricKey(data: password)
    var result: [UInt8] = []
    var block: UInt32 = 1
    while result.count < length {
      var message = salt
      message += [UInt8(block >> 24), UInt8(block >> 16 & 0xFF), UInt8(block >> 8 & 0xFF), UInt8(block & 0xFF)]
      result += Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
      block += 1
    }
    return Array(result.prefix(length))
  }

  /// BlockMix with Salsa20/8 over `b` (2r blocks of 16 words), with `y` and `t` as scratch
  @_optimize(speed)
  private static func blockMix(_ b: UnsafeMutablePointer<UInt32>, _ y: UnsafeMutablePointer<UInt32>, _ t: UnsafeMutablePointer<UInt32>, _ r: Int) {
    t.update(from: b + (2 * r - 1) * 16, count: 16)
    for i in 0..<(2 * r) {
      let block = b + i * 16
      var k = 0
      while k < 16 {
        t[k] ^= block[k]
        k += 1
      }
      salsa8(t)
      // Even blocks go to the first half, odd ones to the second
      (y + (i % 2 == 0 ? i / 2 : r + i / 2) * 16).update(from: t, count: 16)
    }
    b.update(from: y, count: 32 * r)
  }

  @_optimize(speed)
  private static func salsa8(_ b: UnsafeMutablePointer<UInt32>) {
    var x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3], x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7]
    var x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11], x12 = b[12], x13 = b[13], x14 = b[14], x15 = b[15]
    var round = 0
    while round < 4 {
      var a = x0 &+ x12; x4 ^= a << 7 | a >> 25
      a = x4 &+ x0; x8 ^= a << 9 | a >> 23
      a = x8 &+ x4; x12 ^= a << 13 | a >> 19
      a = x12 &+ x8; x0 ^= a << 18 | a >> 14
      a = x5 &+ x1; x9 ^= a << 7 | a >> 25
      a = x9 &+ x5; x13 ^= a << 9 | a >> 23
      a = x13 &+ x9; x1 ^= a << 13 | a >> 19
      a = x1 &+ x13; x5 ^= a << 18 | a >> 14
      a = x10 &+ x6; x14 ^= a << 7 | a >> 25
      a = x14 &+ x10; x2 ^= a << 9 | a >> 23
      a = x2 &+ x14; x6 ^= a << 13 | a >> 19
      a = x6 &+ x2; x10 ^= a << 18 | a >> 14
      a = x15 &+ x11; x3 ^= a << 7 | a >> 25
      a = x3 &+ x15; x7 ^= a << 9 | a >> 23
      a = x7 &+ x3; x11 ^= a << 13 | a >> 19
      a = x11 &+ x7; x15 ^= a << 18 | a >> 14
      a = x0 &+ x3; x1 ^= a << 7 | a >> 25
      a = x1 &+ x0; x2 ^= a << 9 | a >> 23
      a = x2 &+ x1; x3 ^= a << 13 | a >> 19
      a = x3 &+ x2; x0 ^= a << 18 | a >> 14
      a = x5 &+ x4; x6 ^= a << 7 | a >> 25
      a = x6 &+ x5; x7 ^= a << 9 | a >> 23
      a = x7 &+ x6; x4 ^= a << 13 | a >> 19
      a = x4 &+ x7; x5 ^= a << 18 | a >> 14
      a = x10 &+ x9; x11 ^= a << 7 | a >> 25
      a = x11 &+ x10; x8 ^= a << 9 | a >> 23
      a = x8 &+ x11; x9 ^= a << 13 | a >> 19
      a = x9 &+ x8; x10 ^= a << 18 | a >> 14
      a = x15 &+ x14; x12 ^= a << 7 | a >> 25
      a = x12 &+ x15; x13 ^= a << 9 | a >> 23
      a = x13 &+ x12; x14 ^= a << 13 | a >> 19
      a = x14 &+ x13; x15 ^= a << 18 | a >> 14
      round += 1
    }
    b[0] &+= x0; b[1] &+= x1; b[2] &+= x2; b[3] &+= x3; b[4] &+= x4; b[5] &+= x5; b[6] &+= x6; b[7] &+= x7
    b[8] &+= x8; b[9] &+= x9; b[10] &+= x10; b[11] &+= x11; b[12] &+= x12; b[13] &+= x13; b[14] &+= x14; b[15] &+= x15
  }
}
