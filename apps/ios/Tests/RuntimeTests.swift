import XCTest
@testable import FoxVPNCore

final class RuntimeTests: XCTestCase {
    let base = "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp#Fixture"
    func fixture(_ count: Int = 1) throws -> VPNProfile {
        var p = VPNProfile(); _ = try p.importLinks((0..<count).map { base.replacingOccurrences(of: "@example.com", with: "@s\($0).example.com") }.joined(separator: "\n")); return p
    }
    func testOldSettingsRetainSafeDefaults() throws {
        let p = try JSONDecoder().decode(VPNSettings.self, from: Data("{\"mode\":\"vpn\"}".utf8))
        XCTAssertFalse(p.ios.automatic_server); XCTAssertFalse(p.ios.update_on_launch); XCTAssertEqual(p.ios.subscription_hours, 0)
    }
    func testAutomaticPoolIsBoundedAndRespectsFiltersWithoutDroppingManualChoice() throws {
        var p = try fixture(30); p.settings.ios.automatic_server = true
        XCTAssertEqual(p.connectionPool.count, 8)
        p.servers[1].favorite = true; p.servers[1].group = "Work"
        p.settings.ios.favorites_only = true; p.settings.ios.server_group = "Work"
        XCTAssertEqual(p.connectionPool.map(\.id), [p.selected!, p.servers[1].id])
        p.settings.mode = .direct; XCTAssertEqual(p.connectionPool.count, 1)
    }
    func testAutomaticConfigurationKeepsVPNDNSAndRoutesInsideSamePool() throws {
        var p = try fixture(3); p.settings.ios.automatic_server = true
        let json = try JSONSerialization.jsonObject(with: Data(TunnelConfiguration.make(profile: p).utf8)) as! [String: Any]
        let outbounds = json["outbounds"] as! [[String: Any]], automatic = outbounds.first { $0["tag"] as? String == "vpn" }!
        XCTAssertEqual(automatic["type"] as? String, "urltest"); XCTAssertEqual(automatic["outbounds"] as? [String], p.connectionPool.map(\.outboundTag))
        XCTAssertEqual((json["route"] as! [String: Any])["final"] as? String, "vpn")
        XCTAssertEqual((json["route"] as! [String: Any])["default_domain_resolver"] as? String, "dns-direct")
        XCTAssertTrue((automatic["outbounds"] as! [String]).allSatisfy { $0 != "direct" })
        XCTAssertEqual(((json["dns"] as! [String: Any])["servers"] as! [[String: Any]]).first { $0["tag"] as? String == "dns-vpn" }?["detour"] as? String, "vpn")
    }
    func testDueSubscriptionsNeverUnderflowFutureClockAndManualModeIsOff() throws {
        var p = try fixture(); p.subscriptions = [VPNSubscription(id: "old", name: "Old", url: "https://example.com/sub", updated_at: 100), VPNSubscription(id: "future", name: "Future", url: "https://example.com/sub", updated_at: 99999)]
        XCTAssertTrue(p.dueSubscriptions(now: 4000).isEmpty)
        p.settings.ios.subscription_hours = 1; XCTAssertEqual(p.dueSubscriptions(now: 4000), ["old"])
        XCTAssertEqual(p.dueSubscriptions(now: 0, force: true), ["old", "future"])
    }
    func testTrafficRatesResetSafelyAcrossCoreCounterResetAndSleep() {
        var m = TrafficMeter(); m.sample(upload: 100, download: 200, time: 1); m.sample(upload: 300, download: 800, time: 3)
        XCTAssertEqual(m.uploadRate, 100); XCTAssertEqual(m.downloadRate, 300)
        m.sample(upload: 20, download: 50, time: 4); XCTAssertEqual(m.upload, 320); XCTAssertEqual(m.download, 850); XCTAssertEqual(m.downloadRate, 0)
        m.sample(upload: 40, download: 80, time: 30); XCTAssertEqual(m.downloadRate, 0); XCTAssertEqual(m.download, 880)
        m.sample(upload: 999, download: 999, time: 29); XCTAssertEqual(m.download, 880)
    }
    func testTrafficTotalsSaturateWithoutOverflow() {
        var m = TrafficMeter(); m.sample(upload: Int64.max, download: Int64.max, time: 1); m.sample(upload: 5, download: 5, time: 2)
        XCTAssertEqual(m.upload, Int64.max); XCTAssertEqual(m.download, Int64.max)
    }
    func testDraftCreatesIPv6AndEditingPreservesIdentityButClearsChangedMeasurements() throws {
        var draft = ServerDraft(); draft.name = "IPv6"; draft.address = "2001:db8::1"; draft.uuid = "00000000-0000-4000-8000-000000000001"
        let created = try draft.server(); XCTAssertEqual(created.address, "2001:db8::1")
        var old = created; old.latency_ms = 55; old.download_mbps = 20; old.subscription = "sub"
        draft = ServerDraft(server: old); draft.name = "Renamed"; let renamed = try draft.server()
        XCTAssertEqual(renamed.id, old.id); XCTAssertEqual(renamed.latency_ms, 55); XCTAssertEqual(renamed.subscription, "sub")
        draft.port = "444"; XCTAssertNil(try draft.server().latency_ms)
        draft.port = "invalid"; XCTAssertThrowsError(try draft.server())
    }
    func testDraftEnforcesRealityAndTransportValidation() throws {
        let old = try VPNServer.parse(base); var draft = ServerDraft(server: old); draft.security = "reality"
        XCTAssertThrowsError(try draft.server()); draft.flow = "xtls-rprx-vision"; draft.transport = "ws"; XCTAssertThrowsError(try draft.server())
    }
    func testCoreRequestsRejectInjectedPathsAndUnconfiguredTags() throws {
        let tag = "server-abc", tags: Set<String> = [tag]
        XCTAssertNil(CoreRequest(data: Data("{\"measure\":\"../connections\"}".utf8), allowedTags: tags))
        XCTAssertNil(CoreRequest(data: Data(repeating: 0, count: 257), allowedTags: tags))
        XCTAssertNotNil(CoreRequest(data: Data("{\"measure\":\"server-abc\"}".utf8), allowedTags: tags))
        let raw = Data("{\"uploadTotal\":123,\"downloadTotal\":456,\"connections\":[{\"host\":\"private.example.com\",\"uuid\":\"secret\"}]}".utf8)
        let safe = CoreRequest.statistics.safeResponse(raw, allowedTags: tags)!
        XCTAssertFalse(String(decoding: safe, as: UTF8.self).contains("private")); XCTAssertFalse(String(decoding: safe, as: UTF8.self).contains("secret"))
    }
    func testCoreRouteReportIncludesOnlyAllowedTagsAndDelays() throws {
        let input = Data("{\"proxies\":{\"vpn\":{\"now\":\"server-abc\"},\"server-abc\":{\"history\":[{\"delay\":45}],\"uuid\":\"secret\"},\"direct\":{\"history\":[{\"delay\":1}]}}}".utf8)
        let data = CoreRequest.route.safeResponse(input, allowedTags: ["server-abc"])!
        let snapshot = try JSONDecoder().decode(TunnelRouteSnapshot.self, from: data)
        XCTAssertEqual(snapshot.active_tag, "server-abc"); XCTAssertEqual(snapshot.delays, ["server-abc":45]); XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("secret"))
    }
    func testHistoryRoundTripsAndRejectsUnboundedData() throws {
        var p = try fixture(); p.settings.ios.history = [TrafficSession(started: 1000, duration: 10, upload: 11, download: 22)]
        let restored = try JSONDecoder().decode(VPNProfile.self, from: p.exportData()); XCTAssertEqual(restored.settings.ios.history[0].download, 22)
        p.settings.ios.history = Array(repeating: p.settings.ios.history[0], count: 101); XCTAssertThrowsError(try p.validate())
    }
}
