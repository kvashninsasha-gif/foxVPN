import Foundation
import NetworkExtension
import SwiftUI

@MainActor final class VPNController: ObservableObject {
    @Published private(set) var profile = VPNProfile()
    @Published private(set) var status: NEVPNStatus = .disconnected
    @Published private(set) var healthy = false
    @Published private(set) var busy = false
    @Published private(set) var loaded = false
    @Published private(set) var checking = false
    @Published var importPresented = false
    @Published var error: String?
    @Published var notice: String?
    @Published var upload: Int64 = 0
    @Published var download: Int64 = 0
    private let vault: ProfileStoring
    private let backend: TunnelBackend
    private let internet: InternetChecking
    private var healthTask: Task<Void, Never>?
    private var monitorTask: Task<Void, Never>?
    private var epoch = UUID()
    private var revision = UUID()
    private let healthFailure = "Туннель активен, но доступ к интернету не подтверждён. Проверьте сервер и сеть."
    var active: Bool { [.connected, .connecting, .reasserting, .disconnecting].contains(status) }
    var editable: Bool { loaded && !active && !busy }
    var title: String {
        if !loaded { return busy ? "Загружаем профиль" : "Профиль недоступен" }
        switch status { case .connected: return healthy ? "Подключено" : "Проверяем связь"; case .connecting: return "Подключаемся"; case .reasserting: return "Восстанавливаем"; case .disconnecting: return "Отключаемся"; default: return "Отключено" }
    }
    convenience init() {
        self.init(vault: ProcessInfo.processInfo.arguments.contains("--ui-testing") ? MemoryProfileStore() : ProfileVault(), backend: SystemTunnelBackend(), internet: HTTPSInternetChecker())
    }
    init(vault: ProfileStoring, backend: TunnelBackend, internet: InternetChecking, automaticLoad: Bool = true) {
        self.vault = vault; self.backend = backend; self.internet = internet
        backend.onStatusChange = { [weak self] in self?.acceptStatus($0) }
        if automaticLoad { Task { [weak self] in await self?.reload() } }
    }
    deinit { healthTask?.cancel(); monitorTask?.cancel() }
    func reload() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        do {
            try await backend.load()
            let value = try vault.load(); try value.validate()
            profile = value; loaded = true; revision = UUID(); error = nil
            acceptStatus(backend.status)
        } catch {
            // Loading failures never overwrite the old record or allow saving an empty one.
            acceptStatus(backend.status); loaded = false; self.error = "Профиль или настройки VPN не загружены. Разблокируйте iPhone и повторите. Сохранённые данные не заменены."
        }
    }
    private func acceptStatus(_ value: NEVPNStatus) {
        status = value; epoch = UUID(); checking = false
        healthTask?.cancel(); monitorTask?.cancel()
        healthy = false
        if value != .connected { upload = 0; download = 0; return }
        scheduleHealthCheck()
        let token = epoch
        monitorTask = Task { [weak self] in
            var ticks = 0
            while !Task.isCancelled {
                guard let self, self.epoch == token, self.status == .connected else { return }
                await self.refreshStatistics()
                ticks += 1
                if ticks % 5 == 0 { self.scheduleHealthCheck() }
                do { try await Task.sleep(for: .seconds(3)) } catch { return }
            }
        }
    }
    func change(_ update: (inout VPNProfile) throws -> Void) -> Bool {
        guard editable else { error = loaded ? "Сначала отключите VPN и дождитесь завершения операции." : "Сначала загрузите сохранённый профиль."; return false }
        do {
            var copy = profile; try update(&copy); try copy.validate(); try vault.save(copy)
            profile = copy; revision = UUID(); error = nil; return true
        } catch { self.error = error.localizedDescription; return false }
    }
    func importLinks(_ text: String) {
        var count = 0
        if change({ count = try $0.importLinks(text) }) { notice = count == 0 ? "Все серверы уже есть в списке" : "Добавлено серверов: \(count)" }
    }
    func importFile(_ data: Data) {
        do {
            let value = try ProfileImport.parse(data)
            switch value {
            case .links(let text): importLinks(text)
            case .profile(let profile): if change({ $0 = profile }) { notice = "Профиль восстановлен" }
            }
        } catch { self.error = error.localizedDescription }
    }
    func toggleConnection() async {
        guard !busy, (loaded || active) else { return }
        busy = true; error = nil; defer { busy = false }
        do {
            guard backend.supportsTunnel else { throw FoxError.invalid("Симулятор проверяет интерфейс. Для системного VPN установите подписанное приложение на настоящий iPhone.") }
            if active { try await backend.stop(); return }
            guard let server = profile.selectedServer else { throw FoxError.noServer }
            _ = try TunnelConfiguration.make(profile: profile); try vault.save(profile)
            try await backend.start(settings: profile.settings)
            notice = "Подключаем \(server.name)"
        } catch { self.error = error.localizedDescription }
    }
    private func scheduleHealthCheck() {
        guard !checking else { return }
        healthTask = Task { [weak self] in await self?.checkConnection() }
    }
    func checkConnection() async {
        guard status == .connected, !checking else { return }
        checking = true; let token = epoch
        defer { if epoch == token { checking = false } }
        do {
            let result = try await internet.check()
            guard epoch == token, status == .connected, !Task.isCancelled else { return }
            healthy = result
            if !result { error = healthFailure } else if error == healthFailure { error = nil }
        } catch {
            guard epoch == token, status == .connected, !Task.isCancelled else { return }
            healthy = false; self.error = healthFailure
        }
    }
    func refreshStatistics() async {
        guard status == .connected else { return }; let token = epoch
        do {
            let response = try await backend.statistics()
            guard epoch == token, status == .connected, !Task.isCancelled, let response,
                  let values = try JSONSerialization.jsonObject(with: response) as? [String: NSNumber] else { return }
            upload = max(0, values["upload"]?.int64Value ?? 0); download = max(0, values["download"]?.int64Value ?? 0)
        } catch { /* Optional counters never change real VPN status. */ }
    }
    func updateSubscription(_ id: String) async {
        guard editable, let sub = profile.subscriptions.first(where: { $0.id == id }), let url = URL(string: sub.url) else { return }
        busy = true; let token = revision; defer { busy = false }
        do {
            let text = try await SubscriptionFetcher.fetch(url)
            guard !active, token == revision else { throw FoxError.invalid("VPN или профиль изменился. Повторите обновление после отключения.") }
            var copy = profile; try copy.replaceSubscription(id, content: text)
            try vault.save(copy); profile = copy; revision = UUID(); notice = "Подписка обновлена"; error = nil
        } catch { self.error = "Не удалось обновить подписку. Сохранённый список не изменён. " + ((error as? FoxError)?.localizedDescription ?? "") }
    }
}

final class MemoryProfileStore: ProfileStoring {
    private var value = VPNProfile()
    func load() throws -> VPNProfile { value }
    func save(_ profile: VPNProfile) throws { value = profile }
}
