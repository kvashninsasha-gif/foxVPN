import XCTest
import Libbox
@testable import FoxVPN

final class EngineTests: XCTestCase {
    func testActualLibboxAcceptsEveryRoutingAndTransport() throws {
        for transport in ["tcp", "ws", "grpc"] {
            for mode in RoutingMode.allCases {
                var p = VPNProfile()
                _ = try p.importLinks("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=\(transport)&sni=example.com&path=%2Fws&serviceName=grpc#Fixture")
                p.settings.mode = mode; p.rules = [DomainRule(domain: "*.example.ru", route: "vpn")]
                let config = try TunnelConfiguration.make(profile: p)
                var error: NSError?
                XCTAssertTrue(LibboxCheckConfig(config, &error), "\(transport) \(mode): configuration rejected")
                XCTAssertNil(error)
            }
        }
    }
    func testNativeSystemDNSResolvesPublicFixture() throws {
        var data = Data([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]); data.append(try DNSMessage.wireName("example.com")); data.append(contentsOf: [0, 1, 0, 1])
        let query = try DNSQuery(question: DNSMessage(data), interfaceIndex: 0)
        let completed = expectation(description: "DNS answer")
        DispatchQueue.global(qos: .userInitiated).async {
            defer { completed.fulfill() }
            do { let answer = try query.resolve(); XCTAssertEqual(Array(answer.prefix(2)), [0x12, 0x34]); XCTAssertGreaterThan(Int(answer[6]) * 256 + Int(answer[7]), 0) }
            catch { XCTFail("Native DNS failed: \(error.localizedDescription)") }
        }
        wait(for: [completed], timeout: 15)
    }
    func testNativeSystemDNSCancellation() throws {
        var data = Data([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]); data.append(try DNSMessage.wireName("example.com")); data.append(contentsOf: [0, 1, 0, 1])
        let query = try DNSQuery(question: DNSMessage(data), interfaceIndex: 0); query.cancel()
        XCTAssertThrowsError(try query.resolve())
    }
    func testActualLibboxRejectsUnknownOutboundType() {
        let config = "{\"outbounds\":[{\"type\":\"unknown-outbound\",\"tag\":\"vpn\",\"server\":\"example.com\",\"server_port\":443,\"uuid\":\"invalid\"}]}"
        var error: NSError?; XCTAssertFalse(LibboxCheckConfig(config, &error)); XCTAssertNotNil(error)
    }
}
