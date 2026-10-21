import Foundation

/// A JSON value. Objects keep their key order, integers stay exact (`Int`), other numbers are `Double`.
public enum JSON: Sendable, Equatable {
  case null
  case bool(Bool)
  case int(Int)
  case double(Double)
  case string(String)
  case array([JSON])
  case object(JSONObject)

  public subscript(key: String) -> JSON? {
    if case .object(let object) = self { return object[key] }
    return nil
  }
  public var string: String? {
    if case .string(let value) = self { return value }
    return nil
  }
  public var bool: Bool? {
    if case .bool(let value) = self { return value }
    return nil
  }
  /// Integers, and doubles without a fraction
  public var int: Int? {
    switch self {
    case .int(let value): return value
    case .double(let value): return value.rounded() == value && abs(value) < 9.007_199_254_740_992e15 ? Int(value) : nil
    default: return nil
    }
  }
  public var double: Double? {
    switch self {
    case .int(let value): return Double(value)
    case .double(let value): return value
    default: return nil
    }
  }
  public var array: [JSON]? {
    if case .array(let value) = self { return value }
    return nil
  }
  public var object: JSONObject? {
    if case .object(let value) = self { return value }
    return nil
  }
  public var isNull: Bool {
    if case .null = self { return true }
    return false
  }
  /// Strings of an array, skipping other values
  public var strings: [String]? {
    array?.compactMap(\.string)
  }
}

/// A JSON object that keeps insertion order. Setting an existing key replaces its value in place.
public struct JSONObject: Sendable, Equatable, Sequence, ExpressibleByDictionaryLiteral {
  public private(set) var keys: [String] = []
  private var values: [String: JSON] = [:]
  public init() {}
  public init(dictionaryLiteral elements: (String, JSON?)...) {
    for (key, value) in elements { self[key] = value }
  }
  public init(_ pairs: [(String, JSON)]) {
    for (key, value) in pairs { self[key] = value }
  }
  public subscript(key: String) -> JSON? {
    get { values[key] }
    set {
      if let newValue {
        if values.updateValue(newValue, forKey: key) == nil { keys.append(key) }
      } else if values.removeValue(forKey: key) != nil {
        keys.removeAll { $0 == key }
      }
    }
  }
  public var count: Int { keys.count }
  public var isEmpty: Bool { keys.isEmpty }
  public func contains(_ key: String) -> Bool { values[key] != nil }
  public func makeIterator() -> AnyIterator<(key: String, value: JSON)> {
    var index = 0
    return AnyIterator {
      guard index < keys.count else { return nil }
      defer { index += 1 }
      let key = keys[index]
      return (key, values[key]!)
    }
  }
  public static func == (left: JSONObject, right: JSONObject) -> Bool {
    left.values == right.values
  }
}

// MARK: - Literals

extension JSON: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral, ExpressibleByBooleanLiteral,
  ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral, ExpressibleByNilLiteral, ExpressibleByFloatLiteral
{
  public init(stringLiteral value: String) { self = .string(value) }
  public init(integerLiteral value: Int) { self = .int(value) }
  public init(floatLiteral value: Double) { self = .double(value) }
  public init(booleanLiteral value: Bool) { self = .bool(value) }
  public init(arrayLiteral elements: JSON...) { self = .array(elements) }
  public init(dictionaryLiteral elements: (String, JSON?)...) {
    var object = JSONObject()
    for (key, value) in elements { object[key] = value }
    self = .object(object)
  }
  public init(nilLiteral: ()) { self = .null }
}

public extension JSON {
  init(_ value: String?) { self = value.map { .string($0) } ?? .null }
  init(_ values: [String]) { self = .array(values.map { .string($0) }) }
}

// MARK: - Parsing

public struct JSONParseError: Error, CustomStringConvertible {
  public var description: String
}

public extension JSON {
  static func parse(_ text: String) throws -> JSON {
    var text = text
    return try text.withUTF8 { try parse(bytes: $0) }
  }
  static func parse(_ data: Data) throws -> JSON {
    try data.withUnsafeBytes { try parse(bytes: $0.bindMemory(to: UInt8.self)) }
  }
  static func parse(bytes: UnsafeBufferPointer<UInt8>) throws -> JSON {
    var parser = Parser(bytes: bytes)
    parser.skipWhitespace()
    let value = try parser.value(depth: 0)
    parser.skipWhitespace()
    guard parser.index == bytes.count else { throw parser.error("unexpected data after the value") }
    return value
  }
}

private struct Parser {
  let bytes: UnsafeBufferPointer<UInt8>
  var index = 0
  static let maxDepth = 512

  func error(_ text: String) -> JSONParseError {
    JSONParseError(description: "\(text) at \(index)")
  }
  mutating func skipWhitespace() {
    while index < bytes.count {
      switch bytes[index] {
      case 0x20, 0x0A, 0x0D, 0x09: index += 1
      default: return
      }
    }
  }
  mutating func value(depth: Int) throws -> JSON {
    guard depth < Parser.maxDepth else { throw error("too deep") }
    guard index < bytes.count else { throw error("unexpected end") }
    switch bytes[index] {
    case UInt8(ascii: "{"): return try object(depth: depth)
    case UInt8(ascii: "["): return try array(depth: depth)
    case UInt8(ascii: "\""): return .string(try string())
    case UInt8(ascii: "t"): try literal("true"); return .bool(true)
    case UInt8(ascii: "f"): try literal("false"); return .bool(false)
    case UInt8(ascii: "n"): try literal("null"); return .null
    default: return try number()
    }
  }
  mutating func literal(_ text: StaticString) throws {
    let count = text.utf8CodeUnitCount
    guard index + count <= bytes.count else { throw error("invalid literal") }
    for offset in 0..<count where bytes[index + offset] != text.utf8Start[offset] {
      throw error("invalid literal")
    }
    index += count
  }
  mutating func object(depth: Int) throws -> JSON {
    index += 1
    var object = JSONObject()
    skipWhitespace()
    if index < bytes.count, bytes[index] == UInt8(ascii: "}") {
      index += 1
      return .object(object)
    }
    while true {
      skipWhitespace()
      guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else { throw error("expected a key") }
      let key = try string()
      skipWhitespace()
      guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { throw error("expected :") }
      index += 1
      skipWhitespace()
      object[key] = try value(depth: depth + 1)
      skipWhitespace()
      guard index < bytes.count else { throw error("unexpected end") }
      if bytes[index] == UInt8(ascii: ",") {
        index += 1
      } else if bytes[index] == UInt8(ascii: "}") {
        index += 1
        return .object(object)
      } else {
        throw error("expected , or }")
      }
    }
  }
  mutating func array(depth: Int) throws -> JSON {
    index += 1
    var array: [JSON] = []
    skipWhitespace()
    if index < bytes.count, bytes[index] == UInt8(ascii: "]") {
      index += 1
      return .array(array)
    }
    while true {
      skipWhitespace()
      array.append(try value(depth: depth + 1))
      skipWhitespace()
      guard index < bytes.count else { throw error("unexpected end") }
      if bytes[index] == UInt8(ascii: ",") {
        index += 1
      } else if bytes[index] == UInt8(ascii: "]") {
        index += 1
        return .array(array)
      } else {
        throw error("expected , or ]")
      }
    }
  }
  mutating func string() throws -> String {
    index += 1
    let start = index
    // Fast path: no escapes
    while index < bytes.count {
      let byte = bytes[index]
      if byte == UInt8(ascii: "\"") {
        let result = String(decoding: UnsafeBufferPointer(rebasing: bytes[start..<index]), as: UTF8.self)
        index += 1
        return result
      }
      if byte == UInt8(ascii: "\\") { break }
      if byte < 0x20 { throw error("control character in string") }
      index += 1
    }
    var buffer = Array(bytes[start..<index])
    while index < bytes.count {
      let byte = bytes[index]
      switch byte {
      case UInt8(ascii: "\""):
        index += 1
        return String(decoding: buffer, as: UTF8.self)
      case UInt8(ascii: "\\"):
        index += 1
        guard index < bytes.count else { throw error("unexpected end") }
        let escape = bytes[index]
        index += 1
        switch escape {
        case UInt8(ascii: "\""): buffer.append(0x22)
        case UInt8(ascii: "\\"): buffer.append(0x5C)
        case UInt8(ascii: "/"): buffer.append(0x2F)
        case UInt8(ascii: "b"): buffer.append(0x08)
        case UInt8(ascii: "f"): buffer.append(0x0C)
        case UInt8(ascii: "n"): buffer.append(0x0A)
        case UInt8(ascii: "r"): buffer.append(0x0D)
        case UInt8(ascii: "t"): buffer.append(0x09)
        case UInt8(ascii: "u"):
          var scalar = try hex4()
          if (0xD800..<0xDC00).contains(scalar) {
            // A high surrogate needs its low half, otherwise it becomes U+FFFD
            if index + 1 < bytes.count, bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u") {
              index += 2
              let low = try hex4()
              if (0xDC00..<0xE000).contains(low) {
                scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
              } else {
                append(0xFFFD, to: &buffer)
                scalar = low
              }
            } else {
              scalar = 0xFFFD
            }
          } else if (0xDC00..<0xE000).contains(scalar) {
            scalar = 0xFFFD
          }
          append(scalar, to: &buffer)
        default:
          throw error("invalid escape")
        }
      default:
        if byte < 0x20 { throw error("control character in string") }
        buffer.append(byte)
        index += 1
      }
    }
    throw error("unterminated string")
  }
  mutating func hex4() throws -> UInt32 {
    guard index + 4 <= bytes.count else { throw error("invalid \\u escape") }
    var value: UInt32 = 0
    for _ in 0..<4 {
      let byte = bytes[index]
      let digit: UInt32
      switch byte {
      case 0x30...0x39: digit = UInt32(byte - 0x30)
      case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
      case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
      default: throw error("invalid \\u escape")
      }
      value = value << 4 | digit
      index += 1
    }
    return value
  }
  func append(_ scalar: UInt32, to buffer: inout [UInt8]) {
    let scalar = Unicode.Scalar(scalar) ?? "\u{FFFD}"
    buffer.append(contentsOf: Array(String(Character(scalar)).utf8))
  }
  mutating func number() throws -> JSON {
    let start = index
    var isInteger = true
    if index < bytes.count, bytes[index] == UInt8(ascii: "-") { index += 1 }
    guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw error("invalid value") }
    if bytes[index] == 0x30 {
      index += 1
    } else {
      while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
    }
    if index < bytes.count, bytes[index] == UInt8(ascii: ".") {
      isInteger = false
      index += 1
      guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw error("invalid number") }
      while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
    }
    if index < bytes.count, bytes[index] == UInt8(ascii: "e") || bytes[index] == UInt8(ascii: "E") {
      isInteger = false
      index += 1
      if index < bytes.count, bytes[index] == UInt8(ascii: "+") || bytes[index] == UInt8(ascii: "-") { index += 1 }
      guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw error("invalid number") }
      while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
    }
    let text = String(decoding: UnsafeBufferPointer(rebasing: bytes[start..<index]), as: UTF8.self)
    if isInteger, let value = Int(text) { return .int(value) }
    guard let value = Double(text) else { throw error("invalid number") }
    return .double(value)
  }
}

// MARK: - Serialization

public extension JSON {
  /// Compact JSON text
  var text: String {
    var output = ""
    write(to: &output, indent: nil, level: 0)
    return output
  }
  /// Indented with two spaces, for files people read
  var prettyText: String {
    var output = ""
    write(to: &output, indent: "  ", level: 0)
    return output
  }
  var data: Data { Data(text.utf8) }

  private func write(to output: inout String, indent: String?, level: Int) {
    switch self {
    case .null: output += "null"
    case .bool(let value): output += value ? "true" : "false"
    case .int(let value): output += String(value)
    case .double(let value):
      if !value.isFinite {
        output += "null"
      } else if value.rounded() == value, abs(value) < 1e15 {
        output += String(Int(value))
      } else {
        output += "\(value)"
      }
    case .string(let value): JSON.writeString(value, to: &output)
    case .array(let values):
      if values.isEmpty {
        output += "[]"
        return
      }
      output += "["
      for (offset, value) in values.enumerated() {
        if offset > 0 { output += "," }
        if let indent { output += "\n" + String(repeating: indent, count: level + 1) }
        value.write(to: &output, indent: indent, level: level + 1)
      }
      if let indent { output += "\n" + String(repeating: indent, count: level) }
      output += "]"
    case .object(let object):
      if object.isEmpty {
        output += "{}"
        return
      }
      output += "{"
      var first = true
      for (key, value) in object {
        if !first { output += "," }
        first = false
        if let indent { output += "\n" + String(repeating: indent, count: level + 1) }
        JSON.writeString(key, to: &output)
        output += indent == nil ? ":" : ": "
        value.write(to: &output, indent: indent, level: level + 1)
      }
      if let indent { output += "\n" + String(repeating: indent, count: level) }
      output += "}"
    }
  }

  private static func writeString(_ value: String, to output: inout String) {
    output += "\""
    var needsEscape = false
    for byte in value.utf8 where byte < 0x20 || byte == 0x22 || byte == 0x5C {
      needsEscape = true
      break
    }
    if !needsEscape {
      output += value
      output += "\""
      return
    }
    for scalar in value.unicodeScalars {
      switch scalar {
      case "\"": output += "\\\""
      case "\\": output += "\\\\"
      case "\n": output += "\\n"
      case "\r": output += "\\r"
      case "\t": output += "\\t"
      case "\u{08}": output += "\\b"
      case "\u{0C}": output += "\\f"
      default:
        if scalar.value < 0x20 {
          let hex = String(scalar.value, radix: 16)
          output += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
        } else {
          output.unicodeScalars.append(scalar)
        }
      }
    }
    output += "\""
  }
}

extension JSON: CustomStringConvertible {
  public var description: String { text }
}
