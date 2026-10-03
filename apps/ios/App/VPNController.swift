import Foundation
import NetworkExtension
import SwiftUI

@MainActor final class VPNController: ObservableObject {
    @Published private(set) var profile = VPNProfile()
    @Published private(set) var status: NEVPNStatus = .disconnected
    @Published private(set) var healthy = false
    @Published private(set) var busy = false
    @Published private(set) var loaded = false
    @Published var importPresented = false
    @Published var error: String?
    @Published var notice: String?
    @Published var upload: Int64 = 0
    @Published var download: Int64 = 0
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private let vault = ProfileVault()
    private let testing = ProcessInfo.processInfo.arguments.contains("--ui-testing")
    var active: Bool { [.connected, .connecting, .reasserting, .disconnecting].contains(status) }
    var editable: Bool { loaded && !active && !busy }
    var title: String { switch status { case .connected: return healthy ? "Подключено" : "Проверяем связь"; case .connecting: return "Подключаемся"; case .reasserting: return "Восстанавливаем"; case .disconnecting: return "Отключаемся"; default: return "Отключено" } }

    init() {
        do { if !testing { profile = try vault.load() }; loaded = true }
        catch { self.error = "Профиль не загружен. Разблокируйте устройство и откройте приложение снова. Сохранённые данные не заменены." }
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
            Task { @MainActor [weak self] in
                guard let self, let connection = note.object as? NEVPNConnection, connection === self.manager?.connection else { return }
                self.status = connection.status
                if self.status != .connected { self.healthy = false; self.upload = 0; self.download = 0 }
                else { await self.checkConnection() }
            }
        }
        if !testing { Task { await loadManager() } }
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }
    private func loadManager() async {
        do {
            let values = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = values.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.extensionID }
            status = manager?.connection.status ?? .disconnected
            if status == .connected { await checkConnection() }
        } catch { self.error = "Не удалось прочитать настройки VPN iOS." }
    }
    static var extensionID: String { (Bundle.main.bundleIdentifier ?? "ru.smartvpn.router.ios") + ".tunnel" }
    func change(_ update: (inout VPNProfile) throws -> Void) {
        guard editable else { error = "Сначала отключите VPN."; return }
        do { var copy = profile; try update(&copy); try copy.validate(); if !testing { try vault.save(copy) }; profile = copy; error = nil }
        catch { self.error = error.localizedDescription }
    }
    func importLinks(_ text: String) { change { profile in let count = try profile.importLinks(text); notice = "Добавлено серверов: \(count)" } }
    func importFile(_ data: Data) {
        guard data.count <= 4_000_000 else { error = "Файл слишком большой."; return }
        if let text = String(data: data, encoding: .utf8), text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("vless://") { importLinks(text); return }
        change { current in let value = try JSONDecoder().decode(VPNProfile.self, from: data); try value.validate(); current = value; notice = "Профиль восстановлен" }
    }
    func toggleConnection() async {
        guard !busy, loaded else { return }
        busy = true; error = nil; defer { busy = false }
        do {
            #if targetEnvironment(simulator)
            throw FoxError.invalid("Симулятор проверяет интерфейс. Для системного VPN установите подписанное приложение на настоящий iPhone.")
            #else
            if active {
                manager?.isOnDemandEnabled = false
                if let manager { try await manager.saveToPreferences() }
                manager?.connection.stopVPNTunnel(); return
            }
            guard let server = profile.selectedServer else { throw FoxError.noServer }
            _ = try TunnelConfiguration.make(profile: profile)
            try vault.save(profile)
            let value = manager ?? NETunnelProviderManager()
            let configuration = NETunnelProviderProtocol()
            configuration.providerBundleIdentifier = Self.extensionID
            configuration.serverAddress = "foxVPN"
            configuration.providerConfiguration = ["profileVersion": 1]
            configuration.includeAllNetworks = profile.settings.include_all_networks
            configuration.excludeLocalNetworks = false
            value.protocolConfiguration = configuration; value.localizedDescription = "foxVPN"; value.isEnabled = true
            let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
            value.onDemandRules = profile.settings.auto_connect ? [rule] : []
            value.isOnDemandEnabled = profile.settings.auto_connect
            try await value.saveToPreferences(); try await value.loadFromPreferences()
            manager = value; healthy = false
            try value.connection.startVPNTunnel()
            status = value.connection.status
            notice = "Подключаем \(server.name)"
            #endif
        } catch { self.error = error.localizedDescription }
    }
    func checkConnection() async {
        guard status == .connected else { return }
        let configuration = URLSessionConfiguration.ephemeral; configuration.timeoutIntervalForRequest = 12; configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration); defer { session.invalidateAndCancel() }
        do {
            let (_, response) = try await session.data(from: URL(string: "https://www.gstatic.com/generate_204")!)
            guard (response as? HTTPURLResponse)?.statusCode == 204 else { throw FoxError.invalid("Проверка связи не прошла.") }
            if status == .connected { healthy = true; error = nil; notice = nil }
        } catch { if status == .connected { healthy = false; self.error = "Туннель активен, но доступ к интернету не подтверждён. Проверьте сервер и сеть." } }
    }
    func refreshStatistics() async {
        guard status == .connected, let session = manager?.connection as? NETunnelProviderSession else { return }
        do {
            let response: Data? = try await withCheckedThrowingContinuation { continuation in
                do { try session.sendProviderMessage(Data("stats".utf8)) { continuation.resume(returning: $0) } }
                catch { continuation.resume(throwing: error) }
            }
            if let response, let values = try JSONSerialization.jsonObject(with: response) as? [String: NSNumber] { upload = values["upload"]?.int64Value ?? 0; download = values["download"]?.int64Value ?? 0 }
        } catch { /* Counters are optional; never replace real connection status. */ }
    }
    func updateSubscription(_ id: String) async {
        guard editable, let sub = profile.subscriptions.first(where: { $0.id == id }), let url = URL(string: sub.url), url.scheme == "https" else { return }
        busy = true; defer { busy = false }
        do {
            let config = URLSessionConfiguration.ephemeral; config.timeoutIntervalForRequest = 20
            let session = URLSession(configuration: config, delegate: HTTPSRedirectPolicy(), delegateQueue: nil); defer { session.invalidateAndCancel() }
            var data = Data()
            let (bytes, response) = try await session.bytes(from: url)
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode), http.url?.scheme == "https" else { throw FoxError.invalid("Подписка недоступна по HTTPS.") }
            for try await byte in bytes { data.append(byte); if data.count > 4_000_000 { throw FoxError.invalid("Подписка слишком большая.") } }
            let text = try SubscriptionContent.decode(data)
            var replacement = VPNProfile(); _ = try replacement.importLinks(text, subscription: id)
            guard !replacement.servers.isEmpty else { throw FoxError.invalid("В подписке нет корректных серверов.") }
            var copy = profile
            let oldSelected = copy.selectedServer
            let oldServers = copy.servers.filter { $0.subscription == id }
            copy.servers.removeAll { $0.subscription == id }
            for var server in replacement.servers {
                if let old = oldServers.first(where: { $0.fingerprint == server.fingerprint }) { server.id = old.id; server.favorite = old.favorite; server.group = old.group }
                if !copy.servers.contains(where: { $0.fingerprint == server.fingerprint }) { copy.servers.append(server) }
            }
            if let oldSelected, !copy.servers.contains(where: { $0.id == oldSelected.id }) { copy.selected = copy.servers.first(where: { $0.fingerprint == oldSelected.fingerprint })?.id ?? copy.servers.first?.id }
            copy.subscriptions[copy.subscriptions.firstIndex(where: { $0.id == id })!].updated_at = UInt64(Date().timeIntervalSince1970)
            try copy.validate(); if !testing { try vault.save(copy) }; profile = copy; notice = "Подписка обновлена"; error = nil
        } catch { self.error = "Не удалось обновить подписку. Сохранённый список не изменён." }
    }
}

private final class HTTPSRedirectPolicy: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        guard let url = request.url, url.scheme == "https", url.user == nil, url.password == nil else { completionHandler(nil); return }
        completionHandler(request)
    }
}
