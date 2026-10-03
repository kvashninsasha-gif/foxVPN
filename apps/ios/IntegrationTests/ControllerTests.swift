import XCTest
import NetworkExtension
import Security
@testable import FoxVPN

@MainActor final class ControllerTests: XCTestCase {
    private func fixture() throws -> VPNProfile {
        var p = VPNProfile(); _ = try p.importLinks("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=tcp#Fixture"); return p
    }
    func testLoadFailureNeverOverwritesStoredProfileAndCanRetry() async throws {
        let store = TestStore(try fixture()); store.failLoad = true
        let backend = TestBackend(), checker = TestChecker()
        let controller = VPNController(vault: store, backend: backend, internet: checker, automaticLoad: false)
        await controller.reload(); XCTAssertFalse(controller.loaded)
        XCTAssertFalse(controller.change { $0.servers.removeAll() }); XCTAssertEqual(store.saves, 0)
        store.failLoad = false; await controller.reload(); XCTAssertTrue(controller.loaded); XCTAssertEqual(controller.profile.servers.count, 1)
    }
    func testFailedSavePreservesSelectionAndProfile() async throws {
        let store = TestStore(try fixture()), backend = TestBackend()
        let controller = VPNController(vault: store, backend: backend, internet: TestChecker(), automaticLoad: false)
        await controller.reload(); store.failSave = true
        XCTAssertFalse(controller.change { $0.servers.removeAll(); $0.selected = nil })
        XCTAssertEqual(controller.profile.servers.count, 1); XCTAssertEqual(controller.profile.selected, store.value.selected)
    }
    func testLoadingBlocksEarlyConnect() async throws {
        let store = TestStore(try fixture()), backend = TestBackend(); backend.holdLoad = true
        let controller = VPNController(vault: store, backend: backend, internet: TestChecker(), automaticLoad: false)
        let load = Task { await controller.reload() }; await Task.yield()
        XCTAssertTrue(controller.busy); await controller.toggleConnection(); XCTAssertEqual(backend.starts, 0)
        backend.releaseLoad(); await load.value; XCTAssertTrue(controller.loaded)
    }
    func testFailedVaultSavePreventsTunnelStart() async throws {
        let store = TestStore(try fixture()), backend = TestBackend()
        let controller = VPNController(vault: store, backend: backend, internet: TestChecker(), automaticLoad: false)
        await controller.reload(); store.failSave = true; await controller.toggleConnection()
        XCTAssertEqual(backend.starts, 0); XCTAssertFalse(controller.busy)
    }
    func testActiveTunnelLocksEditsAndStopsEvenWhenProfileCannotLoad() async throws {
        let store = TestStore(try fixture()); store.failLoad = true
        let backend = TestBackend(); backend.status = .connected
        let controller = VPNController(vault: store, backend: backend, internet: TestChecker(), automaticLoad: false)
        await controller.reload(); XCTAssertTrue(controller.active); XCTAssertFalse(controller.editable)
        await controller.toggleConnection(); XCTAssertEqual(backend.stops, 1); XCTAssertFalse(controller.active)
    }
    func testLateHealthResponseCannotMarkDisconnectedTunnelHealthy() async throws {
        let store = TestStore(try fixture()), backend = TestBackend(), checker = TestChecker(); checker.hold = true
        let controller = VPNController(vault: store, backend: backend, internet: checker, automaticLoad: false)
        await controller.reload(); backend.emit(.connected)
        while checker.pending == nil { await Task.yield() }
        backend.emit(.disconnected); checker.release(true); await Task.yield()
        XCTAssertFalse(controller.healthy); XCTAssertEqual(controller.status, .disconnected); XCTAssertFalse(controller.checking)
    }
    func testLateStatisticsCannotRestoreOldCountersAfterDisconnect() async throws {
        let store = TestStore(try fixture()), backend = TestBackend(); backend.holdStats = true
        let controller = VPNController(vault: store, backend: backend, internet: TestChecker(), automaticLoad: false)
        await controller.reload(); backend.emit(.connected)
        while backend.pendingStats == nil { await Task.yield() }
        backend.emit(.disconnected); backend.releaseStats(Data("{\"upload\":900,\"download\":1000}".utf8)); await Task.yield()
        XCTAssertEqual(controller.upload, 0); XCTAssertEqual(controller.download, 0)
    }
    func testProviderMessageTimeoutAndLateDuplicateRepliesResumeOnce() async throws {
        let data = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            let reply = ProviderReply(continuation)
            reply.complete(.success(nil)); reply.complete(.success(Data("late".utf8))); reply.complete(.failure(FoxError.storage))
        }
        XCTAssertNil(data)
    }
    func testRealSimulatorKeychainRoundTripUsesIsolatedRecord() throws {
        let service = "ru.smartvpn.router.ios.test." + UUID().uuidString
        defer { SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service] as CFDictionary) }
        let vault = ProfileVault(service: service), profile = try fixture()
        try vault.save(profile); let loaded = try vault.load()
        XCTAssertEqual(loaded.servers, profile.servers); XCTAssertEqual(loaded.selected, profile.selected)
    }
}
private final class TestStore: ProfileStoring {
    var value: VPNProfile; var failLoad = false; var failSave = false; var saves = 0
    init(_ value: VPNProfile) { self.value = value }
    func load() throws -> VPNProfile { if failLoad { throw FoxError.locked }; return value }
    func save(_ profile: VPNProfile) throws { if failSave { throw FoxError.storage }; value = profile; saves += 1 }
}
@MainActor private final class TestBackend: TunnelBackend {
    var status: NEVPNStatus = .disconnected
    var supportsTunnel = true
    var onStatusChange: ((NEVPNStatus) -> Void)?
    var starts = 0; var stops = 0; var holdLoad = false; var holdStats = false
    var pendingLoad: CheckedContinuation<Void, Never>?
    var pendingStats: CheckedContinuation<Data?, Never>?
    func load() async throws { if holdLoad { await withCheckedContinuation { pendingLoad = $0 } } }
    func releaseLoad() { pendingLoad?.resume(); pendingLoad = nil }
    func start(settings: VPNSettings) async throws { starts += 1; emit(.connecting) }
    func stop() async throws { stops += 1; emit(.disconnected) }
    func statistics() async throws -> Data? { if holdStats { return await withCheckedContinuation { pendingStats = $0 } }; return nil }
    func releaseStats(_ data: Data) { pendingStats?.resume(returning: data); pendingStats = nil }
    func emit(_ status: NEVPNStatus) { self.status = status; onStatusChange?(status) }
}
@MainActor private final class TestChecker: InternetChecking {
    var hold = false; var pending: CheckedContinuation<Bool, Never>?
    func check() async throws -> Bool { if hold { return await withCheckedContinuation { pending = $0 } }; return true }
    func release(_ value: Bool) { pending?.resume(returning: value); pending = nil }
}
