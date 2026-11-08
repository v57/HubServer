import XCTest
@testable import ChannelServer
@testable import HubServer

/// protocol.md section 15, as hub-server's test/api-descriptions.test.ts
final class ApiDescriptionsTests: XCTestCase {
  func testHeadersKeepWellFormedFieldsPerKind() throws {
    let input: JSON = ["type": "string"]
    let read = ApiDescriptions.read([
      ["path": "docs/list", "kind": "stream", "description": "Files, then changes.", "annotations": ["readOnlyHint": true, "other": 1, "destructiveHint": "no"]],
      ["path": "docs/list", "kind": "post", "title": .string(String(repeating: "x", count: 129)), "inputSchema": input, "outputSchema": [1]],
      ["path": "docs/list", "kind": "sideways", "description": "no such kind"],
      ["path": "docs/plain"],
    ])
    let list = ApiDescriptions.describe("docs/list", builtinKinds: [], providers: [read["docs/list"]])
    XCTAssertEqual(list, [
      ["path": "docs/list", "kind": "post", "inputSchema": input],
      ["path": "docs/list", "kind": "stream", "description": "Files, then changes.", "annotations": ["readOnlyHint": true]],
    ])
    XCTAssertEqual(ApiDescriptions.describe("docs/plain", builtinKinds: [], providers: [read["docs/plain"]]), [["path": "docs/plain"]])
    XCTAssertEqual(ApiDescriptions.describe("hub/api/list", builtinKinds: [.stream, .post], providers: []), [
      ["path": "hub/api/list", "kind": "post"], ["path": "hub/api/list", "kind": "stream"],
    ])
  }

  func testTheFirstProviderThatDescribedAKindWins() {
    let first = ApiDescriptions.read([["path": "a", "kind": "post"]])["a"]
    let second = ApiDescriptions.read([["path": "a", "kind": "post", "description": "Second."]])["a"]
    let third = ApiDescriptions.read([["path": "a", "kind": "post", "description": "Third."]])["a"]
    XCTAssertEqual(ApiDescriptions.describe("a", builtinKinds: [], providers: [first, nil, second, third]), [["path": "a", "kind": "post", "description": "Second."]])
  }

  func testOversizedSchemasAndDescriptionsAreLeftOut() {
    let big: JSON = ["type": "string", "description": .string(String(repeating: "y", count: ApiDescriptions.schemaLimit))]
    XCTAssertNil(ApiDescriptions.fields(["inputSchema": big, "description": .string(String(repeating: "z", count: 4097))]))
    XCTAssertEqual(ApiDescriptions.fields(["description": .string(String(repeating: "z", count: 4096))])?.count, 1)
  }
}
