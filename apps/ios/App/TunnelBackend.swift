import Foundation
import NetworkExtension

@MainActor protocol TunnelBackend: AnyObject {
    var status: NEVPNStatus { get }
    var supportsTunnel: Bool { get }
    var onStatusChange: ((NEVPNStatus) -> Void)? { get set }
    func load() async throws
    func start(settings: VPNSettings) async throws
    func stop() async throws
    func statistics() async throws -> Data?
}

@MainActor final class SystemTunnelBackend: TunnelBackend {
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    var onStatusChange: ((NEVPNStatus) -> Void)?
    var status: NEVPNStatus { manager?.connection.status ?? .disconnected }
    var supportsTunnel: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }
    static var extensionID: String { (Bundle.main.bundleIdentifier ?? "ru.smartvpn.router.ios") + ".tunnel" }
    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
            Task { @MainActor [weak self] in
                guard let self, let connection = note.object as? NEVPNConnection, connection === self.manager?.connection else { return }
                self.onStatusChange?(connection.status)
            }
        }
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    func load() async throws {
        // iOS Simulator has no system VPN service. Its real Keychain still works.
        guard supportsTunnel else { return }
        let values = try await NETunnelProviderManager.loadAllFromPreferences()
        manager = values.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionID }
    }
    func start(settings: VPNSettings) async throws {
        let value = manager ?? NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = Self.extensionID
        configuration.serverAddress = "foxVPN"
        configuration.providerConfiguration = ["profileVersion": 1]
        configuration.includeAllNetworks = settings.include_all_networks
        configuration.excludeLocalNetworks = false
        value.protocolConfiguration = configuration; value.localizedDescription = "foxVPN"; value.isEnabled = true
        let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
        value.onDemandRules = settings.auto_connect ? [rule] : []
        value.isOnDemandEnabled = settings.auto_connect
        try await value.saveToPreferences(); try await value.loadFromPreferences()
        manager = value
        do { try value.connection.startVPNTunnel() }
        catch { value.isOnDemandEnabled = false; try? await value.saveToPreferences(); value.connection.stopVPNTunnel(); throw error }
        onStatusChange?(value.connection.status)
    }
    func stop() async throws {
        guard let manager else { return }
        manager.isOnDemandEnabled = false
        do { try await manager.saveToPreferences() }
        catch {
            manager.connection.stopVPNTunnel()
            throw FoxError.invalid("VPN остановлен, но iOS не сохранила отключение подключения по требованию. Проверьте системные настройки VPN.")
        }
        manager.connection.stopVPNTunnel()
        onStatusChange?(manager.connection.status)
    }
    func statistics() async throws -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return try await withCheckedThrowingContinuation { continuation in
            let reply = ProviderReply(continuation)
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) { reply.complete(.success(nil)) }
            do { try session.sendProviderMessage(Data("stats".utf8)) { reply.complete(.success($0)) } }
            catch { reply.complete(.failure(error)) }
        }
    }
}

// The extension can die without replying; timeout and late callbacks race safely.
final class ProviderReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Error>?
    init(_ continuation: CheckedContinuation<Data?, Error>) { self.continuation = continuation }
    func complete(_ result: Result<Data?, Error>) {
        lock.lock(); let callback = continuation; continuation = nil; lock.unlock()
        callback?.resume(with: result)
    }
}

@MainActor protocol InternetChecking {
    func check() async throws -> Bool
}
struct HTTPSInternetChecker: InternetChecking {
    func check() async throws -> Bool {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 12; config.timeoutIntervalForResource = 15
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
        let (_, response) = try await session.bytes(from: URL(string: "https://www.gstatic.com/generate_204")!)
        return (response as? HTTPURLResponse)?.statusCode == 204
    }
}
