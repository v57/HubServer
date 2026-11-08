import ChannelServer
import Foundation

// API descriptions (protocol.md section 15): what services say about their paths, kept per connection and listed by
// `hub/api/list`, as hub-server's src/api-descriptions.ts

enum ApiKind: String, CaseIterable {
  case post, stream
}

/// What one connection said about one path
struct PathDescriptions {
  /// Kinds its headers named
  var kinds = Set<ApiKind>()
  var fields: [ApiKind: JSONObject] = [:]
}

enum ApiDescriptions {
  static let titleLimit = 128
  static let descriptionLimit = 4096
  static let schemaLimit = 64 * 1024
  static let annotationKeys = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]

  /// The description fields of a `ServiceHeader` the hub keeps; anything malformed or too large is left out
  static func fields(_ header: JSON) -> JSONObject? {
    var fields = JSONObject()
    if let title = text(header["title"], limit: titleLimit) { fields["title"] = .string(title) }
    if let description = text(header["description"], limit: descriptionLimit) { fields["description"] = .string(description) }
    if let input = schema(header["inputSchema"]) { fields["inputSchema"] = input }
    if let output = schema(header["outputSchema"]) { fields["outputSchema"] = output }
    if let annotations = header["annotations"]?.object {
      var kept = JSONObject()
      for key in annotationKeys {
        if case .bool(let value)? = annotations[key] { kept[key] = .bool(value) }
      }
      if !kept.isEmpty { fields["annotations"] = .object(kept) }
    }
    return fields.isEmpty ? nil : fields
  }

  /// A connection's descriptions from the headers of a `services` update, by path
  static func read(_ headers: [JSON]) -> [String: PathDescriptions] {
    var result: [String: PathDescriptions] = [:]
    for header in headers {
      guard let path = header["path"]?.string else { continue }
      var entry = result[path] ?? PathDescriptions()
      if let kind = header["kind"]?.string.flatMap(ApiKind.init(rawValue:)) {
        entry.kinds.insert(kind)
        if entry.fields[kind] == nil, let fields = fields(header) { entry.fields[kind] = fields }
      }
      result[path] = entry
    }
    return result
  }

  /// The `hub/api/list` entries of one path: one per kind that a built-in or a provider's header named, with the
  /// fields of the first provider that described it; `{ path }` when nothing named a kind
  static func describe(_ path: String, builtinKinds: Set<ApiKind>, providers: [PathDescriptions?]) -> [JSON] {
    var kinds = builtinKinds
    for provider in providers { kinds.formUnion(provider?.kinds ?? []) }
    guard !kinds.isEmpty else { return [["path": .string(path)]] }
    return ApiKind.allCases.filter(kinds.contains).map { kind in
      var entry: JSONObject = ["path": .string(path), "kind": .string(kind.rawValue)]
      if let fields = providers.lazy.compactMap({ $0?.fields[kind] }).first {
        for (key, value) in fields { entry[key] = value }
      }
      return .object(entry)
    }
  }

  private static func text(_ value: JSON?, limit: Int) -> String? {
    guard let value = value?.string, !value.isEmpty, value.utf16.count <= limit else { return nil }
    return value
  }

  private static func schema(_ value: JSON?) -> JSON? {
    guard let value, value.object != nil, value.text.utf8.count <= schemaLimit else { return nil }
    return value
  }
}
