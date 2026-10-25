import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#endif
@testable import HubServer

private func fixture(_ name: String) throws -> JSON {
  try JSON.parse(Data(contentsOf: Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures")!))
}

/// hub-server's src/network/crypto.test.ts and foundation.test.ts, with its vectors
final class NetworkFoundationTests: XCTestCase {
  func testSignatureVectors() throws {
    let vectors = try fixture("network-crypto-v1")
    let seed = Data(stride(from: 0, to: 64, by: 2).map { offset -> UInt8 in
      let text = vectors["seed"]!.string!
      let start = text.index(text.startIndex, offsetBy: offset)
      return UInt8(text[start...text.index(after: start)], radix: 16)!
    })
    let key = HubKeyPair(privateKey: try Curve25519.Signing.PrivateKey(rawRepresentation: seed))
    XCTAssertEqual(key.publicKey, vectors["publicKey"]!.string)
    for vector in vectors["vectors"]!.array! {
      let purpose = SignaturePurpose(rawValue: vector["purpose"]!.string!)!
      let envelope = vector["envelope"]!
      let input = NetworkSignature.input(purpose, envelope)
      XCTAssertEqual(HubCrypto.hex(HubCrypto.sha256(input)), vector["inputSha256"]!.string, purpose.rawValue)
      var signed = envelope.object!
      signed["signature"] = vector["signature"]!
      XCTAssertTrue(NetworkSignature.verify(purpose, .object(signed), publicKey: key.publicKey), purpose.rawValue)
      // CryptoKit signs with randomness: ours differ from the vector but verify
      signed["signature"] = .string(NetworkSignature.sign(purpose, envelope, key: key))
      XCTAssertTrue(NetworkSignature.verify(purpose, .object(signed), publicKey: key.publicKey), purpose.rawValue)
    }
    // Every purpose has its own domain; mutation and cross-purpose replay fail
    XCTAssertEqual(Set(SignaturePurpose.allCases.map(\.domain)).count, SignaturePurpose.allCases.count)
    let grant = vectors["vectors"]!.array![2]
    var signed = grant["envelope"]!.object!
    signed["signature"] = grant["signature"]!
    XCTAssertFalse(NetworkSignature.verify(.rendezvousTicket, .object(signed), publicKey: key.publicKey))
    signed["generation"] = 5
    XCTAssertFalse(NetworkSignature.verify(.connectionGrant, .object(signed), publicKey: key.publicKey))
  }

  func testCanonicalJSON() throws {
    let value = try JSON.parse(#"{"b":[1,{"z":true,"a":null}],"a":"é\"\n","A":1.5,"_":0}"#)
    XCTAssertEqual(NetworkSignature.canonicalJSON(value), #"{"A":1.5,"_":0,"a":"é\"\n","b":[1,{"a":null,"z":true}]}"#)
    XCTAssertEqual(NetworkSignature.javascriptNumber(1e-7), "1e-7")
    XCTAssertEqual(NetworkSignature.javascriptNumber(1e21), "1e+21")
    XCTAssertEqual(NetworkSignature.javascriptNumber(2.5), "2.5")
  }

  func testIdentityVectors() throws {
    let ownerA = Data((0..<32).map { UInt8($0) }).base64EncodedString()
    let ownerB = Data((0..<32).map { UInt8(255 - $0) }).base64EncodedString()
    let hubA = "018f0f67-89ab-7def-8123-456789abcdef"
    XCTAssertEqual(try NetworkFoundation.stableResourceId(ownerKey: ownerA, shareName: "s3"), "hnr1_vu5lgvuep3ijwvktdc3c7jtlkbq7tpio")
    XCTAssertEqual(try NetworkFoundation.canonicalAuthority(hubNetworkId: hubA, ownerKey: ownerA, shareName: "s3"),
      "s3-vu5lgvuep3ijwvkt.v1-rtmx5wwkl7ux5ivb.hub.invalid")
    XCTAssertEqual(try NetworkFoundation.canonicalAuthority(hubNetworkId: hubA, ownerKey: ownerA, shareName: "Café Storage"),
      "cafe-storage-wueyutzkbjcidw6f.v1-rtmx5wwkl7ux5ivb.hub.invalid")
    XCTAssertNotEqual(try NetworkFoundation.stableResourceId(ownerKey: ownerA, shareName: "s3"),
      try NetworkFoundation.stableResourceId(ownerKey: ownerB, shareName: "s3"))
    XCTAssertEqual(try NetworkFoundation.stableResourceId(ownerKey: String(ownerA.dropLast()), shareName: "s3"),
      try NetworkFoundation.stableResourceId(ownerKey: ownerA, shareName: "s3"))
    XCTAssertNotEqual(try NetworkFoundation.stableResourceId(ownerKey: ownerA, shareName: "ab\u{0}c"),
      try NetworkFoundation.stableResourceId(ownerKey: ownerA, shareName: "ab"))
    XCTAssertEqual(try NetworkFoundation.normalizeShareName("  Cafe\u{301}  "), "Café")
    XCTAssertThrowsError(try NetworkFoundation.normalizeShareName("   "))
    XCTAssertEqual(NetworkFoundation.displayLabel("Mac Studio"), "mac-studio")
    XCTAssertEqual(NetworkFoundation.displayLabel("Агент"), "share")
  }

  func testTimes() {
    XCTAssertEqual(NetworkTime.parse("2026-10-13T00:00:00Z")?.timeIntervalSince1970, 1_791_849_600)
    XCTAssertEqual(NetworkTime.parse("2026-10-13T00:00:00.250Z")?.timeIntervalSince1970, 1_791_849_600.25)
    XCTAssertEqual(NetworkTime.parse("2026-10-13T02:00:00.123456789+02:00")!.timeIntervalSince1970, 1_791_849_600.123456789, accuracy: 0.000001)
    XCTAssertNil(NetworkTime.parse("2026-10-13"))
    XCTAssertEqual(NetworkTime.parse(isoDate(Date(timeIntervalSince1970: 1000.5)))?.timeIntervalSince1970, 1000.5)
  }

  func testAddresses() {
    let first = OverlayAddress(ip: NetworkFoundation.ipv6First)!
    XCTAssertEqual(first.ip, "fd48:5542:4e45::1")
    XCTAssertEqual(OverlayAddress(decimal: first.decimal), first)
    XCTAssertEqual(first.decimal, "336670257565496506414968023450478706689")
    XCTAssertEqual(first.next.ip, "fd48:5542:4e45::2")
    XCTAssertEqual(OverlayAddress(ip: NetworkFoundation.ipv6Last)!.ip, NetworkFoundation.ipv6Last)
    XCTAssertEqual(OverlayAddress(ip: "100.96.0.255")!.next.ip, "100.96.1.0")
    XCTAssertEqual(OverlayAddress(ip: "100.96.0.1")!.decimal, "1684013057")
    XCTAssertEqual(OverlayAddress(ip: "fd48:0:0:1:0:0:0:1")!.ip, "fd48:0:0:1::1")
  }
}

/// A connection for driving `NetworkAPI` directly, attached to `device` or with a pending certificate from it
private func connection(_ key: String?, device: String? = nil, attached: Bool = true) -> HubConnection {
  let connection = HubConnection(key: key, ip: "127.0.0.1")
  if let device, let key {
    connection.certificate = Certificate(device: "", deviceId: device, service: key, instance: "agent", iat: 0, exp: 0)
    if attached { connection.device = device }
  }
  return connection
}

private func bindRequest(_ wireGuardKey: String, kind: String = "apple-app", admission: JSON? = nil) -> JSON {
  var object: JSONObject = ["version": 1, "bindingKind": .string(kind), "wireGuardKey": .string(wireGuardKey), "overlayAddresses": [],
    "connectedAt": .string(isoNow()), "name": "Mac Studio"]
  if let admission { object["admission"] = admission }
  return .object(object)
}

/// hub-server's test/network-devices.test.ts and test/join-admission.test.ts
final class NetworkAPITests: XCTestCase {
  var storage: Storage!
  var security: Security!
  var api: NetworkAPI!
  let deviceA = String(repeating: "a", count: 32)
  let deviceB = String(repeating: "b", count: 32)

  override func setUp() {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    storage = Storage(directory: directory, queue: .main, log: { _ in })
    let hubKey = HubKeyPair()
    security = Security(storage: storage, hubKey: hubKey.publicKey)
    security.load(hubKeyExisted: false)
    api = NetworkAPI(storage: storage, security: security, key: hubKey, queue: .main)
    api.load()
  }

  func owner() -> HubKeyPair {
    let key = HubKeyPair()
    security.addOwner(key.publicKey)
    return key
  }

  func bind(_ request: JSON, _ connection: HubConnection) throws -> JSON {
    var result: Result<JSON, Error>?
    api.bind(request, connection: connection, path: "hub/net/bind") { result = $0 }
    return try XCTUnwrap(result).get()
  }

  func code(_ body: () throws -> Any) -> String? {
    do {
      _ = try body()
      return nil
    } catch {
      return (error as? ChannelFailure)?.code?.string ?? "\(error)"
    }
  }

  func testDeviceAttachedAgentIsADeviceMember() throws {
    let agent = owner()
    let result = try bind(bindRequest("wg-a"), connection(agent.publicKey, device: deviceA))
    let profile = result["profile"]!
    XCTAssertEqual(profile["key"]?.string, agent.publicKey)
    XCTAssertEqual(profile["member"]?.string, "device:\(deviceA)")
    XCTAssertEqual(profile["device"]?.string, deviceA)
    XCTAssertTrue(api.registry.hasAllocation("device:\(deviceA)"))
    XCTAssertFalse(api.registry.hasAllocation(agent.publicKey))
    XCTAssertEqual(api.registry.members["device:\(deviceA)"], StoredMember(key: agent.publicKey, device: deviceA, wireGuardKey: "wg-a",
      name: "Mac Studio", platform: nil, lastSeen: api.registry.members["device:\(deviceA)"]!.lastSeen))
    let member = api.listMembers().first { $0["key"]?.string == agent.publicKey }!
    let authority = NetworkFoundation.deviceAuthority(hubNetworkId: api.registry.hubNetworkId, deviceId: deviceA, deviceName: "Mac Studio")
    XCTAssertEqual(member["online"], true)
    XCTAssertEqual(member["deviceAuthority"]?.string, authority)
    XCTAssertNotNil(authority.range(of: "^mac-studio-[a-z2-7]{16}\\.v1-[a-z2-7]{16}\\.hub\\.invalid$", options: .regularExpression))
    XCTAssertEqual(api.deviceNetworkState(deviceA), "online")
    XCTAssertEqual(api.deviceOverlay(deviceA)?["address"], profile["overlayAddresses"]?.array?.first)
    XCTAssertEqual(profile["overlayAddresses"]?.strings, ["100.96.0.1", "fd48:5542:4e45::1"])
    // Offline members keep their member key and device
    api.agents.unregisterProfile(agent.publicKey)
    let offline = api.listMembers()[0]
    XCTAssertEqual(offline["online"], false)
    XCTAssertEqual(offline["member"]?.string, "device:\(deviceA)")
    XCTAssertEqual(offline["device"]?.string, deviceA)
  }

  func testLegacyAgentMovesToItsDevice() throws {
    let agent = owner()
    let legacy = try bind(bindRequest("wg-a"), connection(agent.publicKey))
    XCTAssertEqual(legacy["profile"]?["member"]?.string, agent.publicKey)
    XCTAssertNil(legacy["profile"]?["device"])
    let attached = try bind(bindRequest("wg-a"), connection(agent.publicKey, device: deviceA))
    XCTAssertEqual(attached["profile"]?["overlayAddresses"], legacy["profile"]?["overlayAddresses"])
    XCTAssertFalse(api.registry.hasAllocation(agent.publicKey))
    XCTAssertTrue(api.registry.hasAllocation("device:\(deviceA)"))
  }

  func testOneEndpointPerDevice() throws {
    let first = owner()
    let second = owner()
    let firstConnection = connection(first.publicKey, device: deviceA)
    let bound = try bind(bindRequest("wg-a"), firstConnection)
    let again = connection(first.publicKey, device: deviceA)
    _ = try bind(bindRequest("wg-a"), again)
    XCTAssertEqual(code { try self.bind(bindRequest("wg-b"), connection(second.publicKey, device: self.deviceA)) }, "device_endpoint_exists")
    // A reinstall: the old agent is gone, the new key keeps the addresses with its own WireGuard key
    api.disconnected(firstConnection)
    api.disconnected(again)
    let replaced = try bind(bindRequest("wg-b"), connection(second.publicKey, device: deviceA))
    XCTAssertEqual(replaced["profile"]?["overlayAddresses"], bound["profile"]?["overlayAddresses"])
    XCTAssertEqual(api.registry.members["device:\(deviceA)"]?.key, second.publicKey)
    XCTAssertEqual(api.registry.members["device:\(deviceA)"]?.wireGuardKey, "wg-b")
    XCTAssertEqual(code { try self.bind(bindRequest("wg-a"), connection(first.publicKey, device: self.deviceA)) }, "device_endpoint_exists")
  }

  func testBindApprovesAPendingDevice() throws {
    let agent = owner()
    let pending = connection(agent.publicKey, device: deviceA, attached: false)
    var approved: [String] = []
    api.onBindApprove = { connection in
      approved.append(connection.certificate!.deviceId)
      connection.device = connection.certificate!.deviceId
    }
    _ = try bind(bindRequest("wg-a"), pending)
    XCTAssertEqual(approved, [deviceA])
    XCTAssertTrue(api.registry.hasAllocation("device:\(deviceA)"))
  }

  func testRemovingADeviceRevokesItsMember() throws {
    let agent = owner()
    let lost = owner()
    _ = try bind(bindRequest("wg-a"), connection(agent.publicKey, device: deviceA))
    _ = try bind(bindRequest("wg-lost"), connection(lost.publicKey))
    var pushed = 0
    api.onRevokedDevicesChanged = { pushed += 1 }
    api.removeDevice(deviceA, revokedKeys: [lost.publicKey])
    XCTAssertFalse(api.registry.hasAllocation("device:\(deviceA)"))
    XCTAssertFalse(api.registry.hasAllocation(lost.publicKey))
    XCTAssertEqual(api.registry.released.count, 2)
    XCTAssertTrue(api.listMembers().isEmpty)
    XCTAssertNil(api.deviceNetworkState(deviceA))
    XCTAssertEqual(pushed, 1)
    let revoked = api.revokedDevices(connection(owner().publicKey))
    XCTAssertEqual(revoked.count, 1)
    XCTAssertEqual(revoked[0]["device"]?.string, deviceA)
    XCTAssertEqual(revoked[0]["wireGuardKeys"]?.strings?.sorted(), ["wg-a", "wg-lost"])
    XCTAssertEqual(api.revokedDevices(connection(HubKeyPair().publicKey)), [])
  }

  func testARemovedDeviceThatBindsAgainLeavesTheRevokedList() throws {
    let agent = owner()
    _ = try bind(bindRequest("wg-a"), connection(agent.publicKey, device: deviceA))
    api.removeDevice(deviceA, revokedKeys: [])
    XCTAssertEqual(api.registry.revokedDevices.count, 1)
    _ = try bind(bindRequest("wg-a2"), connection(agent.publicKey, device: deviceA))
    XCTAssertTrue(api.registry.revokedDevices.isEmpty)
  }

  func testReleasedAddressesAreReusedADayLater() throws {
    let registry = api.registry
    let first = try registry.allocateAddresses("one")
    registry.removeMember("one")
    registry.nextIPv4 = registry.lastIPv4.next
    XCTAssertThrowsError(try registry.allocateAddresses("two"))
    registry.released[0].at = isoDate(Date().addingTimeInterval(-25 * 60 * 60))
    let reused = try registry.allocateAddresses("two")
    XCTAssertEqual(reused.ipv4, first.ipv4)
    XCTAssertEqual(reused.ipv6, first.ipv6)
  }

  func testAShareFrontedByAnAgentOnAnotherDeviceIsRefused() throws {
    let agent = owner()
    let service = HubKeyPair()
    _ = try bind(bindRequest("wg-a"), connection(agent.publicKey, device: deviceA))
    func share() -> [JSON] {
      let now = Date()
      var attestation: JSON = ["version": 1, "attestationId": .string(UUID().uuidString), "serviceKey": .string(service.publicKey),
        "key": .string(agent.publicKey), "shareName": "files", "protocol": "tcp", "target": ["host": "127.0.0.1", "port": 9000],
        "issuedAt": .string(isoDate(now)), "expiresAt": .string(isoDate(now.addingTimeInterval(60))), "signature": ""]
      var object = attestation.object!
      object["signature"] = .string(NetworkSignature.sign(.agentAttestation, attestation, key: agent))
      attestation = .object(object)
      return [["version": 1, "name": "files", "protocol": "tcp", "target": ["host": "127.0.0.1", "port": 9000], "attestation": attestation]]
    }
    XCTAssertEqual(code { try self.api.replaceShares(share(), connection: connection(service.publicKey, device: self.deviceB)) }, "share_device_mismatch")
    let publications = try api.replaceShares(share(), connection: connection(service.publicKey, device: deviceA))
    XCTAssertEqual(publications[0]["port"], 9000)
    XCTAssertEqual(publications[0]["protocol"], "tcp")
    XCTAssertEqual(publications[0]["overlayAddress"], "100.96.0.1")
    // A private share: the owner gets grants, a stranger is refused
    let resourceId = publications[0]["resourceId"]!.string!
    XCTAssertEqual(code { try self.api.connectionGrant(["resourceId": .string(resourceId), "callerWireGuardKey": "x"], connection: connection(HubKeyPair().publicKey)) }, "unauthorized")
    let grant = try api.connectionGrant(["resourceId": .string(resourceId), "callerWireGuardKey": "wg-a"], connection: connection(agent.publicKey, device: deviceA))
    XCTAssertTrue(NetworkSignature.verify(.connectionGrant, grant, publicKey: api.registry.hubKey))
    XCTAssertEqual(grant["destinationPort"], 9000)
    XCTAssertEqual(grant["callerAddress"], "100.96.0.1")
  }

  // MARK: Join admission, signed by hub-service-go

  func testJoinAdmissionValidation() throws {
    let admission = try fixture("join-admission")["admission"]!
    let issuedAt = NetworkTime.parse(admission["issuedAt"]?.string)!
    let joiner = admission["joinerServiceKey"]!.string!
    let joinerWireGuard = admission["joinerWireGuardKey"]!.string!
    XCTAssertTrue(NetworkValidation.joinAdmission(admission, joinerKey: joiner, joinerWireGuardKey: joinerWireGuard, now: issuedAt.addingTimeInterval(1)))
    XCTAssertFalse(NetworkValidation.joinAdmission(admission, joinerKey: admission["inviterServiceKey"]!.string!, joinerWireGuardKey: joinerWireGuard, now: issuedAt))
    XCTAssertFalse(NetworkValidation.joinAdmission(admission, joinerKey: joiner, joinerWireGuardKey: admission["inviterWireGuardKey"]!.string!, now: issuedAt))
    var tampered = admission.object!
    tampered["hubProHost"] = "100.96.0.9"
    XCTAssertFalse(NetworkValidation.joinAdmission(.object(tampered), joinerKey: joiner, joinerWireGuardKey: joinerWireGuard, now: issuedAt))
    let expired = NetworkTime.parse(admission["expiresAt"]?.string)!.addingTimeInterval(0.001)
    XCTAssertFalse(NetworkValidation.joinAdmission(admission, joinerKey: joiner, joinerWireGuardKey: joinerWireGuard, now: expired))
  }

  func testJoinBinds() throws {
    let admission = try fixture("join-admission")["admission"]!
    let joiner = admission["joinerServiceKey"]!.string!
    let wireGuard = admission["joinerWireGuardKey"]!.string!
    // The admission's times are in the past: these checks stop before its lifetime matters, or expect the refusal
    XCTAssertEqual(code { try self.bind(bindRequest(wireGuard, kind: "join"), connection(joiner)) }, "forbidden")
    // The inviter isn't bound
    XCTAssertEqual(code { try self.bind(bindRequest(wireGuard, kind: "join", admission: admission), connection(joiner)) }, "forbidden")
    api.agents.registerProfile(AgentProfile(wireGuardKey: admission["inviterWireGuardKey"]!.string!, key: admission["inviterServiceKey"]!.string!,
      overlayAddresses: [], connectedAt: isoNow()), connectionId: "inviter")
    // Presented by another key
    XCTAssertEqual(code { try self.bind(bindRequest(wireGuard, kind: "join", admission: admission), connection(admission["inviterServiceKey"]!.string!)) }, "forbidden")
    // The fixture expired long ago, so it is refused now; a member re-binds without one
    XCTAssertEqual(code { try self.bind(bindRequest(wireGuard, kind: "join", admission: admission), connection(joiner)) }, "forbidden")
    _ = try api.registry.allocateAddresses(joiner)
    let again = try bind(bindRequest(wireGuard, kind: "join"), connection(joiner))
    XCTAssertEqual(again["profile"]?["overlayAddresses"]?.array?.count, 2)
  }

  func testFreshJoinAdmission() throws {
    // An inviter bound to this network signs an admission for a new joiner
    let inviter = HubKeyPair()
    let joiner = HubKeyPair()
    api.agents.registerProfile(AgentProfile(wireGuardKey: "wg-inviter", key: inviter.publicKey, overlayAddresses: [], connectedAt: isoNow()),
      connectionId: "inviter")
    let now = Date()
    var admission: JSON = ["version": 1, "signatureDomain": "hub-network/direct-bootstrap-response/v1", "replayId": "r",
      "inviterServiceKey": .string(inviter.publicKey), "joinerServiceKey": .string(joiner.publicKey), "joinerWireGuardKey": "wg-joiner",
      "inviterWireGuardKey": "wg-inviter", "endpoints": [], "joinerAddress": ["ipv4": "100.127.255.254", "ipv6": "fd48:5542:4e45:ffff::fffe"],
      "inviterAddress": ["ipv4": "100.127.255.253", "ipv6": "fd48:5542:4e45:ffff::fffd"], "hubProHost": "100.127.255.253",
      "issuedAt": .string(isoDate(now)), "expiresAt": .string(isoDate(now.addingTimeInterval(120)))]
    var object = admission.object!
    object["signature"] = .string(NetworkSignature.sign(.directBootstrapResponse, admission, key: inviter))
    admission = .object(object)
    let first = try bind(bindRequest("wg-joiner", kind: "join", admission: admission), connection(joiner.publicKey))
    XCTAssertEqual(first["profile"]?["key"]?.string, joiner.publicKey)
    XCTAssertNil(first["profile"]?["admission"])
    // Re-binds without it; a new WireGuard key needs a fresh admission
    _ = try bind(bindRequest("wg-joiner", kind: "join"), connection(joiner.publicKey))
    XCTAssertEqual(code { try self.bind(bindRequest("wg-other", kind: "join"), connection(joiner.publicKey)) }, "forbidden")
    api.agents.unregisterProfile(joiner.publicKey)
    let member = api.listMembers().first { $0["key"]?.string == joiner.publicKey }!
    XCTAssertEqual(member["online"], false)
    XCTAssertEqual(member["wireGuardKey"], "wg-joiner")
  }

  func testAppleAgentBindNeedsAnOwnerAndReadiness() throws {
    let agent = owner()
    let stranger = HubKeyPair()
    XCTAssertEqual(code { try self.bind(bindRequest("wg-s"), connection(stranger.publicKey)) }, "forbidden")
    let agentConnection = connection(agent.publicKey)
    _ = try bind(bindRequest("wg-a"), agentConnection)
    let now = Date()
    var assertion: JSON = ["version": 1, "signatureDomain": "hub-network/apple-app-agent-readiness/v1",
      "hubNetworkId": .string(api.registry.hubNetworkId), "wireGuardKey": "wg-a", "tunnelInstanceId": "t1",
      "capabilities": ["invitation-bootstrap-v1"], "generation": 1, "issuedAt": .string(isoDate(now)),
      "expiresAt": .string(isoDate(now.addingTimeInterval(20)))]
    var object = assertion.object!
    object["signature"] = .string(NetworkSignature.sign(.appleAppAgentReadiness, assertion, key: agent))
    assertion = .object(object)
    let status = try api.appleAgent(["version": 1, "assertion": assertion], connection: agentConnection, renew: false)
    XCTAssertEqual(status["state"], "available")
    XCTAssertEqual(status["bindingKind"], "apple-app")
    api.disconnected(agentConnection)
    XCTAssertEqual(api.localAgent.status()["state"], "unbound")
  }

  func testMachineProof() throws {
    let agent = HubKeyPair()
    let now = Date()
    var proof: JSON = ["version": 1, "key": .string(agent.publicKey), "connectionId": "c1", "nonce": "n1",
      "capabilities": ["invitation-bootstrap-v1"], "issuedAt": .string(isoDate(now)), "expiresAt": .string(isoDate(now.addingTimeInterval(30)))]
    var object = proof.object!
    object["signature"] = .string(agent.sign(data: LocalAgent.proofInput(proof)))
    proof = .object(object)
    XCTAssertNoThrow(try LocalAgent.validate(proof, key: agent.publicKey, connectionId: "c1", nonce: "n1"))
    XCTAssertThrowsError(try LocalAgent.validate(proof, key: agent.publicKey, connectionId: "c2", nonce: "n1"))
    let bindings = api.localAgent
    try bindings.registerMachine(key: agent.publicKey, connectionId: "c1", proof: proof)
    XCTAssertEqual(bindings.status()["state"], "available")
    // Another key needs an owner's authorization
    let other = HubKeyPair()
    var otherProof = proof.object!
    otherProof["key"] = .string(other.publicKey)
    XCTAssertThrowsError(try bindings.registerMachine(key: other.publicKey, connectionId: "c2", proof: .object(otherProof)))
    try bindings.authorizeRebind(other.publicKey)
    XCTAssertNoThrow(try bindings.registerMachine(key: other.publicKey, connectionId: "c2", proof: .object(otherProof)))
  }

  func testMembersGetASignedHubLinkToTheHubsMachine() throws {
    // The hub's machine: an owner bound as the Apple app agent
    let machine = owner()
    let machineConnection = connection(machine.publicKey)
    _ = try bind(bindRequest("wg-machine"), machineConnection)
    let now = Date()
    var assertion: JSON = ["version": 1, "signatureDomain": "hub-network/apple-app-agent-readiness/v1",
      "hubNetworkId": .string(api.registry.hubNetworkId), "wireGuardKey": "wg-machine", "tunnelInstanceId": "t1",
      "capabilities": ["invitation-bootstrap-v1"], "generation": 1, "issuedAt": .string(isoDate(now)),
      "expiresAt": .string(isoDate(now.addingTimeInterval(20)))]
    var object = assertion.object!
    object["signature"] = .string(NetworkSignature.sign(.appleAppAgentReadiness, assertion, key: machine))
    assertion = .object(object)
    _ = try api.appleAgent(["version": 1, "assertion": assertion], connection: machineConnection, renew: false)

    let phone = owner()
    let phoneConnection = connection(phone.publicKey)
    _ = try bind(bindRequest("wg-phone"), phoneConnection)
    api.hubPort = 1997

    let links = try api.links(phoneConnection, coordinator: "wss://v57.dev:1964")
    XCTAssertEqual(links["coordinator"], "wss://v57.dev:1964")
    XCTAssertEqual(links["hubHost"], false)
    let grant = try XCTUnwrap(links["grants"]?.array?.first)
    XCTAssertEqual(grant["purpose"], "hub")
    XCTAssertEqual(grant["a"]?["key"]?.string, phone.publicKey)
    XCTAssertEqual(grant["a"]?["wireGuardKey"], "wg-phone")
    XCTAssertEqual(grant["b"]?["key"]?.string, machine.publicKey)
    XCTAssertEqual(grant["b"]?["wireGuardKey"], "wg-machine")
    let machineAddresses = try XCTUnwrap(grant["b"]?["addresses"]?.strings)
    XCTAssertEqual(grant["aViaB"]?.strings, machineAddresses.map(NetworkAPI.hostRoute))
    XCTAssertEqual(grant["aToB"], [["protocol": "tcp", "port": 1997]])
    XCTAssertTrue(NetworkSignature.verify(.peerLink, grant, publicKey: api.registry.hubKey))
    // The same sides get the same grant until half its life has passed
    XCTAssertEqual(try api.links(phoneConnection, coordinator: "x")["grants"]?.array?.first?["grantId"], grant["grantId"])

    // The machine itself accepts links and gets none of its own
    let own = try api.links(machineConnection, coordinator: "wss://v57.dev:1964")
    XCTAssertEqual(own["hubHost"], true)
    XCTAssertEqual(own["grants"], [])
    // Without a registered profile there's nothing to link
    let stranger = connection(HubKeyPair().publicKey)
    XCTAssertEqual(code { try self.api.links(stranger, coordinator: "x") }, "unauthorized")
  }

}
