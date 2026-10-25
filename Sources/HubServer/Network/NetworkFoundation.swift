import ChannelServer
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// Hub Network foundations, as hub-server's src/network/foundation.ts and crypto.ts (protocol.md section 10).
// Everything signed must match hub-server byte for byte: canonical JSON, domains and framing.

enum NetworkFoundation {
  static let wireVersion = 1
  static let dnsSuffix = "hub.invalid"
  static let ipv4First = "100.96.0.1"
  static let ipv4Last = "100.127.254.254"
  static let ipv6First = "fd48:5542:4e45::1"
  static let ipv6Last = "fd48:5542:4e45:ffff:ffff:ffff:ffff:fffe"

  private static let base32Alphabet = Array("abcdefghijklmnopqrstuvwxyz234567".utf8)

  static func base32(_ bytes: [UInt8]) -> String {
    var value: UInt32 = 0
    var bits = 0
    var result: [UInt8] = []
    for byte in bytes {
      value = (value << 8) | UInt32(byte)
      bits += 8
      while bits >= 5 {
        result.append(base32Alphabet[Int((value >> UInt32(bits - 5)) & 31)])
        bits -= 5
      }
    }
    if bits > 0 { result.append(base32Alphabet[Int((value << UInt32(5 - bits)) & 31)]) }
    return String(decoding: result, as: UTF8.self)
  }

  /// SHA-256 of the domain, a zero byte, then each field as a 4-byte big-endian length and its UTF-8 bytes
  static func digest(_ domain: String, _ fields: String...) -> [UInt8] {
    var data = Data(domain.utf8)
    data.append(0)
    for field in fields {
      let encoded = Array(field.utf8)
      let length = UInt32(encoded.count)
      data.append(contentsOf: [UInt8(length >> 24), UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF)])
      data.append(contentsOf: encoded)
    }
    return Array(SHA256.hash(data: data))
  }

  /// Re-encodes base64, so unpadded and padded keys give the same resource ids
  static func normalizeKey(_ key: String) -> String {
    var padded = key
    while padded.count % 4 != 0 { padded += "=" }
    return Data(base64Encoded: padded)?.base64EncodedString() ?? ""
  }

  static func normalizeShareName(_ name: String) throws -> String {
    let normalized = name.precomposedStringWithCompatibilityMapping.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty, normalized.utf8.count <= 128 else { throw ChannelFailure("invalid network share name") }
    return normalized
  }

  static func stableResourceId(ownerKey: String, shareName: String) throws -> String {
    let name = try normalizeShareName(shareName)
    return "hnr1_" + String(base32(digest("hub-network/resource/v1", normalizeKey(ownerKey), name)).prefix(32))
  }

  /// Lowercase ASCII letters and digits joined by `-`, at most 24 characters
  static func displayLabel(_ name: String) -> String {
    let folded = name.decomposedStringWithCompatibilityMapping.lowercased()
    var label = ""
    var dash = false
    for scalar in folded.unicodeScalars {
      if (0x300...0x36F).contains(scalar.value) { continue }
      if ("a"..."z").contains(scalar) || ("0"..."9").contains(scalar) {
        label.unicodeScalars.append(scalar)
        dash = false
      } else if !dash {
        label += "-"
        dash = true
      }
    }
    while label.hasPrefix("-") { label.removeFirst() }
    while label.hasSuffix("-") { label.removeLast() }
    if label.isEmpty { label = "share" }
    var short = String(label.prefix(24))
    while short.hasSuffix("-") { short.removeLast() }
    return short.isEmpty ? "share" : short
  }

  private static func hubPart(_ hubNetworkId: String) -> String {
    String(base32(digest("hub-network/authority-hub/v1", hubNetworkId)).prefix(16))
  }

  static func canonicalAuthority(hubNetworkId: String, ownerKey: String, shareName: String) throws -> String {
    let resource = try stableResourceId(ownerKey: ownerKey, shareName: shareName)
    let part = resource.dropFirst(5).prefix(16)
    return "\(displayLabel(shareName))-\(part).v1-\(hubPart(hubNetworkId)).\(dnsSuffix)"
  }

  /// DNS name of a device member: its label, 16 characters of the device id digest and the hub part
  static func deviceAuthority(hubNetworkId: String, deviceId: String, deviceName: String) -> String {
    let device = String(base32(digest("hub-network/device/v1", deviceId)).prefix(16))
    return "\(displayLabel(deviceName))-\(device).v1-\(hubPart(hubNetworkId)).\(dnsSuffix)"
  }
}

// MARK: - Signatures

enum SignaturePurpose: String, CaseIterable {
  case agentAttestation = "agent-attestation"
  case profileBinding = "profile-binding"
  case connectionGrant = "connection-grant"
  case rendezvousTicket = "rendezvous-ticket"
  case networkInvitation = "network-invitation"
  case gatewayGrant = "gateway-grant"
  case appleAppAgentReadiness = "apple-app-agent-readiness"
  case directBootstrapResponse = "direct-bootstrap-response"
  case peerLink = "peer-link"

  var domain: String {
    switch self {
    case .agentAttestation: "hub-network/agent-attestation/v1"
    case .profileBinding: "hub-network/profile-binding/v1"
    case .connectionGrant: "hub-network/connection-grant/v1"
    case .rendezvousTicket: "hub-network/rendezvous-ticket/v1"
    case .networkInvitation: "hub-network/invitation/v1"
    case .gatewayGrant: "hub-network/gateway-grant/v1"
    case .appleAppAgentReadiness: "hub-network/apple-app-agent-readiness/v1"
    case .directBootstrapResponse: "hub-network/direct-bootstrap-response/v1"
    case .peerLink: "hub-network/peer-link/v1"
    }
  }
}

enum NetworkSignature {
  /// JSON with object keys sorted (UTF-16 order, as JavaScript sorts) and no whitespace, strings and numbers as
  /// `JSON.stringify` writes them
  static func canonicalJSON(_ value: JSON) -> String {
    switch value {
    case .object(let object):
      let keys = object.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
      return "{" + keys.map { JSON.string($0).text + ":" + canonicalJSON(object[$0]!) }.joined(separator: ",") + "}"
    case .array(let values):
      return "[" + values.map(canonicalJSON).joined(separator: ",") + "]"
    case .double(let number):
      return javascriptNumber(number)
    default:
      return value.text
    }
  }

  /// `Number.prototype.toString` for the doubles that reach signed envelopes
  static func javascriptNumber(_ value: Double) -> String {
    if value.rounded() == value, abs(value) < 1e21 { return String(format: "%.0f", value) }
    var text = "\(value)"
    // Swift writes 1e-07, JavaScript 1e-7
    if let e = text.firstIndex(of: "e") {
      let mantissa = text[..<e]
      var exponent = String(text[text.index(after: e)...])
      let sign = exponent.hasPrefix("-") ? "-" : "+"
      exponent = exponent.trimmingCharacters(in: CharacterSet(charactersIn: "+-"))
      while exponent.hasPrefix("0") && exponent.count > 1 { exponent.removeFirst() }
      text = "\(mantissa)e\(sign)\(exponent)"
    }
    return text
  }

  /// The domain, a zero byte, the payload length (4 bytes, big-endian), then the canonical JSON of the envelope
  /// without its `signature`
  static func input(_ purpose: SignaturePurpose, _ envelope: JSON) -> Data {
    var unsigned = envelope.object ?? [:]
    unsigned["signature"] = nil
    let payload = Array(canonicalJSON(.object(unsigned)).utf8)
    var data = Data(purpose.domain.utf8)
    data.append(0)
    let length = UInt32(payload.count)
    data.append(contentsOf: [UInt8(length >> 24), UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF)])
    data.append(contentsOf: payload)
    return data
  }

  static func sign(_ purpose: SignaturePurpose, _ envelope: JSON, key: HubKeyPair) -> String {
    key.sign(data: input(purpose, envelope))
  }

  static func verify(_ purpose: SignaturePurpose, _ envelope: JSON, publicKey: String) -> Bool {
    guard let signature = envelope["signature"]?.string, let data = Data(base64Encoded: signature),
      let key = HubCrypto.publicKey(spki: publicKey)
    else { return false }
    return key.isValidSignature(data, for: input(purpose, envelope))
  }
}

// MARK: - Times

enum NetworkTime {
  static let connectionGrantLifetime: TimeInterval = 5 * 60
  static let rendezvousTicketLifetime: TimeInterval = 10 * 60
  static let gatewayGrantLifetime: TimeInterval = 5 * 60
  static let appleReadinessLifetime: TimeInterval = 30
  static let directBootstrapLifetime: TimeInterval = 10 * 60
  static let clockSkew: TimeInterval = 30

  /// ISO 8601 as `Date.parse` reads it: any number of fraction digits, `Z` or an offset
  static func parse(_ text: String?) -> Date? {
    guard let text, text.count >= 20 else { return nil }
    let scanner = Array(text.utf8)
    func number(_ start: Int, _ length: Int) -> Int? {
      guard start + length <= scanner.count else { return nil }
      var value = 0
      for byte in scanner[start..<(start + length)] {
        guard (48...57).contains(byte) else { return nil }
        value = value * 10 + Int(byte - 48)
      }
      return value
    }
    guard let year = number(0, 4), scanner[4] == 45, let month = number(5, 2), scanner[7] == 45, let day = number(8, 2),
      scanner[10] == 84 || scanner[10] == 116, let hour = number(11, 2), scanner[13] == 58, let minute = number(14, 2),
      scanner[16] == 58, let second = number(17, 2)
    else { return nil }
    var index = 19
    var fraction = 0.0
    if index < scanner.count, scanner[index] == 46 {
      index += 1
      var scale = 0.1
      let start = index
      while index < scanner.count, (48...57).contains(scanner[index]) {
        fraction += Double(scanner[index] - 48) * scale
        scale /= 10
        index += 1
      }
      guard index > start else { return nil }
    }
    guard index < scanner.count else { return nil }
    var offset = 0
    if scanner[index] == 90 || scanner[index] == 122 {
      index += 1
    } else if scanner[index] == 43 || scanner[index] == 45 {
      let sign = scanner[index] == 45 ? -1 : 1
      guard let hours = number(index + 1, 2), scanner.count > index + 3, scanner[index + 3] == 58, let minutes = number(index + 4, 2) else { return nil }
      offset = sign * (hours * 3600 + minutes * 60)
      index += 6
    } else {
      return nil
    }
    guard index == scanner.count, (1...12).contains(month), (1...31).contains(day), hour < 24, minute < 60, second < 61 else { return nil }
    var components = DateComponents()
    components.year = year
    components.month = month
    components.day = day
    components.hour = hour
    components.minute = minute
    components.second = second
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC")!
    guard let date = calendar.date(from: components) else { return nil }
    return date.addingTimeInterval(fraction - TimeInterval(offset))
  }

  static func hasValidLifetime(_ issued: JSON?, _ expires: JSON?, maximum: TimeInterval, now: Date) -> Bool {
    guard let issuedAt = parse(issued?.string), let expiresAt = parse(expires?.string) else { return false }
    return issuedAt <= now.addingTimeInterval(clockSkew) && expiresAt > now && expiresAt > issuedAt
      && expiresAt.timeIntervalSince(issuedAt) <= maximum
  }
}

// MARK: - Validation

enum NetworkValidation {
  /// An inviter-signed direct bootstrap response for this joiner's service and WireGuard keys, still valid. The
  /// caller checks that the inviter is a current agent of this network.
  static func joinAdmission(_ admission: JSON, joinerKey: String, joinerWireGuardKey: String, now: Date = Date()) -> Bool {
    guard admission["version"]?.int == NetworkFoundation.wireVersion,
      admission["signatureDomain"]?.string == SignaturePurpose.directBootstrapResponse.domain,
      admission["joinerServiceKey"]?.string == joinerKey, admission["joinerWireGuardKey"]?.string == joinerWireGuardKey,
      NetworkTime.hasValidLifetime(admission["issuedAt"], admission["expiresAt"], maximum: NetworkTime.directBootstrapLifetime, now: now),
      let inviter = admission["inviterServiceKey"]?.string
    else { return false }
    return NetworkSignature.verify(.directBootstrapResponse, admission, publicKey: inviter)
  }

  /// An extension-signed readiness assertion of one Apple packet tunnel
  static func appleReadiness(_ assertion: JSON, key: String, now: Date = Date(), hubNetworkId: String) -> Bool {
    guard assertion["version"]?.int == NetworkFoundation.wireVersion,
      assertion["signatureDomain"]?.string == SignaturePurpose.appleAppAgentReadiness.domain,
      assertion["capabilities"] == ["invitation-bootstrap-v1"], assertion["hubNetworkId"]?.string == hubNetworkId,
      NetworkTime.hasValidLifetime(assertion["issuedAt"], assertion["expiresAt"], maximum: NetworkTime.appleReadinessLifetime, now: now)
    else { return false }
    return NetworkSignature.verify(.appleAppAgentReadiness, assertion, publicKey: key)
  }
}

/// An error of the Hub Network API: hub-server throws `{ version, code, message, retryable }`, which reaches clients as
/// the message with the code
func networkError(_ code: String, _ message: String) -> ChannelFailure {
  ChannelFailure(message, code: .string(code))
}
