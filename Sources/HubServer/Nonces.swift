import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// How long a `hub/info` challenge stays valid, in seconds
let nonceLifetime = 60
/// Most used nonces kept. Reaching it changes the secret instead of growing or forgetting a nonce that still counts.
let usedNoncesLimit = 65536

/// The challenges v1 tokens sign (protocol.md section 2). Handing one out stores nothing: it carries its expiry and a
/// MAC under a secret that lives only in this process, so a restart invalidates them all. Only a token whose signature
/// verified records its nonce as used, until the nonce's own expiry. Runs on the hub's queue.
final class TokenNonces {
  private var secret = SymmetricKey(size: .bits256)
  /// Used nonces and when each stops being valid anyway
  private var used: [String: Int] = [:]
  private let limit: Int

  init(limit: Int = usedNoncesLimit) {
    self.limit = limit
  }

  var usedCount: Int { used.count }

  func issue(now: Int = Int(Date().timeIntervalSince1970)) -> String {
    var body = Data(count: 8)
    let expiry = UInt64(now + nonceLifetime)
    for index in 0..<8 { body[index] = UInt8(truncatingIfNeeded: expiry >> (56 - 8 * index)) }
    var generator = SystemRandomNumberGenerator()
    for _ in 0..<16 { body.append(UInt8.random(in: 0...255, using: &generator)) }
    return HubCrypto.base64URLEncode(body + mac(body))
  }

  /// Whether this hub made the nonce and it hasn't expired. Costs one HMAC, so it runs before the signature check.
  func isValid(_ nonce: String, now: Int = Int(Date().timeIntervalSince1970)) -> Bool {
    expiry(of: nonce, now: now) != nil && used[nonce] == nil
  }

  /// Records the nonce of a token whose signature verified. False when it can't be used (again).
  func consume(_ nonce: String, now: Int = Int(Date().timeIntervalSince1970)) -> Bool {
    guard let expiry = expiry(of: nonce, now: now), used[nonce] == nil else { return false }
    if used.count >= limit { used = used.filter { $0.value > now } }
    if used.count >= limit {
      // Full of nonces that still count: the old secret goes with them, so none of them can come back. This one too.
      secret = SymmetricKey(size: .bits256)
      used = [:]
      return false
    }
    used[nonce] = expiry
    return true
  }

  private func expiry(of nonce: String, now: Int) -> Int? {
    guard nonce.utf8.count <= 128, let bytes = HubCrypto.base64URLDecode(nonce), bytes.count == 40,
      HubCrypto.base64URLEncode(bytes) == nonce
    else { return nil }
    let body = Data(bytes.prefix(24))
    guard constantTimeEqual(mac(body), Data(bytes.suffix(16))) else { return nil }
    let expiry = body.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    guard expiry <= UInt64(Int.max), Int(expiry) > now else { return nil }
    return Int(expiry)
  }

  private func mac(_ body: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: body, using: secret)).prefix(16)
  }

  private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
  }
}

/// A client nonce `hub/info` proves the hub's key over
func isClientNonce(_ nonce: String) -> Bool {
  (16...128).contains(nonce.utf8.count)
    && nonce.utf8.allSatisfy { byte in
      (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || byte == 0x2D || byte == 0x5F
    }
}

/// The string `proof` signs
func hubInfoSignedData(hubKey: String, nonce: String) -> String {
  "hubinfo1:\(hubKey):\(nonce)"
}
