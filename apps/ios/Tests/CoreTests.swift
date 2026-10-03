import XCTest
@testable import FoxVPNCore

final class CoreTests: XCTestCase {
    let base = "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp&sni=example.com#Test"
    func profile() throws -> VPNProfile { var p = VPNProfile(); _ = try p.importLinks(base); return p }
    func testIPv6AndParametersRoundTrip() throws {
        let value = try VPNServer.parse(base.replacingOccurrences(of: "@example.com:", with: "@[2001:db8::1]:") + "")
        XCTAssertEqual(value.address, "2001:db8::1"); XCTAssertEqual(try VPNServer.parse(value.uri()).fingerprint, value.fingerprint)
    }
    func testRejectsInvalidUUIDBeforeReachingEngine() { XCTAssertThrowsError(try VPNServer.parse(base.replacingOccurrences(of: "00000000-0000-4000-8000-000000000001", with: "invalid"))) }
    func testDuplicatesAreNotAdded() throws { var p = try profile(); XCTAssertEqual(try p.importLinks(base), 0); XCTAssertEqual(p.servers.count, 1) }
    func testAtomicMalformedBatch() throws {
        var p = try profile(); let before = try JSONEncoder().encode(p)
        XCTAssertThrowsError(try p.importLinks(base.replacingOccurrences(of: "example.com", with: "new.example.com") + "\nnot-a-link"))
        XCTAssertEqual(p.servers.count, 1); XCTAssertEqual(try JSONDecoder().decode(VPNProfile.self, from: before).servers, p.servers)
    }
    func testRejectsTLSBypassAndDuplicateParameters() {
        XCTAssertThrowsError(try VPNServer.parse(base.replacingOccurrences(of: "#Test", with: "&allowInsecure=true#Test")))
        XCTAssertThrowsError(try VPNServer.parse(base.replacingOccurrences(of: "#Test", with: "&sni=other.example.com#Test")))
    }
    func testRealityRequiresValidKeyAndCompatibleFlow() throws {
        let key = Data(repeating: 7, count: 32).base64EncodedString().replacingOccurrences(of: "=", with: "").replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let link = base.replacingOccurrences(of: "security=tls", with: "security=reality").replacingOccurrences(of: "#Test", with: "&pbk=\(key)&sid=aa&flow=xtls-rprx-vision#Test")
        XCTAssertNoThrow(try VPNServer.parse(link)); XCTAssertThrowsError(try VPNServer.parse(link.replacingOccurrences(of: "type=tcp", with: "type=ws")))
        XCTAssertThrowsError(try VPNServer.parse(link.replacingOccurrences(of: "sid=aa", with: "sid=a")))
    }
    func testWildcardDoesNotMatchApexAndModePrecedence() throws {
        var p = try profile(); p.rules = [DomainRule(domain: "*.example.ru", route: "vpn")]
        XCTAssertEqual(try p.route(for: "example.ru"), "direct"); XCTAssertEqual(try p.route(for: "x.example.ru"), "vpn")
        p.settings.mode = .direct; XCTAssertEqual(try p.route(for: "x.example.ru"), "direct")
        p.settings.mode = .vpn; XCTAssertEqual(try p.route(for: "example.ru"), "vpn")
    }
    func testIDNAndInvalidDomains() throws {
        XCTAssertEqual(try DomainRule.normalize("Пример.РФ"), "xn--e1afmkfd.xn--p1ai")
        for input in ["https://example.com", "127.0.0.1", "foo..com", "a-.com", "foo.com/path", ".example.com"] { XCTAssertThrowsError(try DomainRule.normalize(input)) }
    }
    func testDesktopProfileDecodesDefaults() throws {
        var p = try profile(); let data = try JSONEncoder().encode(p)
        var json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        json["settings"] = ["mode": "smart", "tun": true, "kill_switch": true, "restore": true]
        p = try JSONDecoder().decode(VPNProfile.self, from: JSONSerialization.data(withJSONObject: json))
        XCTAssertEqual(p.settings.dns_transport, "https"); XCTAssertTrue(p.settings.include_all_networks); try p.validate()
    }
    func testRejectsMissingSelectionAndDuplicateRules() throws {
        var p = try profile(); p.selected = "missing"; XCTAssertThrowsError(try p.validate())
        p.selected = p.servers.first?.id; p.rules = [DomainRule(domain: "EXAMPLE.com", route: "vpn"), DomainRule(domain: "example.com", route: "direct")]; XCTAssertThrowsError(try p.validate())
    }
    func testSubscriptionEncodingsAndMalformedData() throws {
        let data = Data(base.utf8)
        XCTAssertEqual(try SubscriptionContent.decode(data), base)
        for encoded in [data.base64EncodedString(), data.base64EncodedString().replacingOccurrences(of: "=", with: "").replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")] { XCTAssertEqual(try SubscriptionContent.decode(Data(encoded.utf8)), base) }
        XCTAssertThrowsError(try SubscriptionContent.decode(Data("invalid".utf8)))
    }
    func testDNSWireRoundTripAndMalformedQuestions() throws {
        var data = Data([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]); data.append(try DNSMessage.wireName("example.com")); data.append(contentsOf: [0, 1, 0, 1])
        let question = try DNSMessage(data); XCTAssertEqual(question.name, "example.com."); XCTAssertEqual(question.type, 1)
        let answer = try DNSMessage.answer(name: "example.com.", type: 1, recordClass: 1, ttl: 60, payload: Data([192, 0, 2, 1]))
        let response = question.response(answers: [answer]); XCTAssertEqual(Array(response.prefix(8)), [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1]); XCTAssertEqual(response.count, data.count + answer.count)
        XCTAssertThrowsError(try DNSMessage(Data(data.dropLast())))
        var compressed = data; compressed[12] = 0xc0; XCTAssertThrowsError(try DNSMessage(compressed))
    }
    func testConfigurationDNSAndDomainPriority() throws {
        var p = try profile(); p.rules = [DomainRule(domain: "*.example.ru", route: "vpn")]
        let json = try JSONSerialization.jsonObject(with: Data(TunnelConfiguration.make(profile: p).utf8)) as! [String: Any]
        let route = json["route"] as! [String: Any], rules = route["rules"] as! [[String: Any]]
        XCTAssertEqual(rules[0]["action"] as? String, "sniff"); XCTAssertEqual(rules[1]["action"] as? String, "hijack-dns")
        XCTAssertEqual(rules[2]["outbound"] as? String, "vpn"); XCTAssertNotNil(rules[3]["domain_suffix"])
        XCTAssertNil(json["experimental"]); XCTAssertEqual((json["inbounds"] as! [[String: Any]]).count, 1)
    }
    func testFingerprintsDoNotCollideOnParameterSeparators() throws {
        var a = try VPNServer.parse(base), b = a
        a.params["a"] = "x=y"; b.params["a=x"] = "y"
        XCTAssertNotEqual(a.fingerprint, b.fingerprint)
    }
    func testLargeImportDeduplicatesWithoutLosingServers() throws {
        let links = (0..<2000).map { base.replacingOccurrences(of: "example.com", with: "vpn-\($0).example.com") }.joined(separator: "\n")
        var p = VPNProfile(); XCTAssertEqual(try p.importLinks(links), 2000); XCTAssertEqual(try p.importLinks(links), 0)
        XCTAssertEqual(p.servers.count, 2000); try p.validate()
    }
    func testSubscriptionReplacementPreservesSelectionAndPersonalMetadata() throws {
        var p = VPNProfile(); let sub = VPNSubscription(id: "fixture-sub", name: "Fixture", url: "https://example.com/sub")
        p.subscriptions = [sub]; _ = try p.importLinks(base, subscription: sub.id)
        p.servers[0].favorite = true; p.servers[0].group = "Work"; p.servers[0].name = "My server"
        let selected = p.selected
        try p.replaceSubscription(sub.id, content: base + "\n" + base.replacingOccurrences(of: "example.com", with: "second.example.com"))
        XCTAssertEqual(p.selected, selected); XCTAssertEqual(p.servers[0].name, "My server"); XCTAssertTrue(p.servers[0].favorite); XCTAssertEqual(p.servers[0].group, "Work")
        XCTAssertEqual(p.subscriptions[0].server_count, 2)
        let before = p.servers; XCTAssertThrowsError(try p.replaceSubscription(sub.id, content: "invalid")); XCTAssertEqual(p.servers, before)
    }
    func testSubscriptionRemovalCanKeepOrRemoveOwnedServers() throws {
        var p = VPNProfile(); p.subscriptions = [VPNSubscription(id: "sub", name: "Fixture", url: "https://example.com/sub")]
        _ = try p.importLinks(base, subscription: "sub"); let selected = p.selected
        var removed = p; removed.removeSubscription("sub", removeServers: true); XCTAssertTrue(removed.servers.isEmpty); XCTAssertNil(removed.selected); try removed.validate()
        p.removeSubscription("sub", removeServers: false); XCTAssertEqual(p.selected, selected); XCTAssertNil(p.servers[0].subscription); try p.validate()
    }
    func testExportUsesDesktopFieldsAndReimports() throws {
        var p = try profile(); p.settings.dns_transport = "local"
        p.subscriptions = [VPNSubscription(id: "sub", name: "Fixture", url: "https://example.com/sub")]; p.servers[0].subscription = "sub"
        let data = try p.exportData(); let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual((json["settings"] as! [String: Any])["dns_protection"] as? Bool, false)
        XCTAssertEqual((json["subscriptions"] as! [[String: Any]])[0]["server_count"] as? Int, 1)
        guard case .profile(let restored) = try ProfileImport.parse(data) else { return XCTFail("Expected profile") }
        XCTAssertEqual(restored.servers, p.servers); XCTAssertEqual(restored.selected, p.selected)
    }
    func testFileImportBOMAndMalformedProfile() throws {
        let text = Data(("\u{feff}" + base).utf8)
        guard case .links(let links) = try ProfileImport.parse(text) else { return XCTFail("Expected links") }
        XCTAssertEqual(links, base)
        XCTAssertThrowsError(try ProfileImport.parse(Data("{bad".utf8)))
        XCTAssertThrowsError(try ProfileImport.parse(Data([0xff, 0xfe])))
    }
    func testSmartTopLevelDomainMatchesEngineSuffixRules() throws {
        let p = try profile(); XCTAssertEqual(try p.route(for: "ru"), "direct"); XCTAssertEqual(try p.route(for: "рф"), "direct")
    }

}
