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
    private var presentedModals: Set<UUID> = []
    var importPresented: Bool { !presentedModals.isEmpty }
    func beginEditingSheet(_ id: UUID) { presentedModals.insert(id); error = nil }
    func endEditingSheet(_ id: UUID) { presentedModals.remove(id); error = nil }
    @Published var error: String?
    @Published var notice: String?
    @Published var upload: Int64 = 0
    @Published var download: Int64 = 0
    @Published private(set) var uploadRate = 0.0
    @Published private(set) var downloadRate = 0.0
    @Published private(set) var testingSpeed = false
    @Published private(set) var speedResult: SpeedResult?
    private var speedTask: Task<Void, Never>?
    private let speedChecker: SpeedChecking
    @Published private(set) var testingServers = false
    @Published private(set) var activeServerID: String?
    @Published private(set) var delays: [String: Int] = [:]
    @Published private(set) var diagnostics: [String] = []
    private var traffic = TrafficMeter()
    private var sessionStarted: Date?
    private var sessionUptime: Double?
    private var subscriptionTask: Task<Void, Never>?
    private var foreground = true
    private var updatedOnLaunch = false
    private var automaticAttempts: [String: Date] = [:]
    private let subscriptionFetch: (URL) async throws -> String
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
    init(vault: ProfileStoring, backend: TunnelBackend, internet: InternetChecking, automaticLoad: Bool = true, speedChecker: SpeedChecking = HTTPSSpeedChecker(), subscriptionFetch: @escaping (URL) async throws -> String = { try await SubscriptionFetcher.fetch($0) }) {
        self.vault = vault; self.backend = backend; self.internet = internet; self.subscriptionFetch = subscriptionFetch; self.speedChecker = speedChecker
        backend.onStatusChange = { [weak self] in self?.acceptStatus($0) }
        if automaticLoad { Task { [weak self] in await self?.reload() } }
    }
    deinit { healthTask?.cancel(); monitorTask?.cancel(); subscriptionTask?.cancel(); speedTask?.cancel() }
    func reload() async {
        guard !busy else { return }; busy = true; defer { busy = false }
        do {
            try await backend.load()
            let value = try vault.load(); try value.validate()
            profile = value; loaded = true; revision = UUID(); error = nil
            acceptStatus(backend.status); log("Профиль загружен"); setForeground(foreground)
        } catch {
            // Loading failures never overwrite the old record or allow saving an empty one.
            acceptStatus(backend.status); loaded = false; self.error = "Профиль или настройки VPN не загружены. Разблокируйте iPhone и повторите. Сохранённые данные не заменены."
        }
    }
    private func acceptStatus(_ value: NEVPNStatus) {
        guard value != status else { return }
        if [.disconnected, .invalid].contains(value) { finishSession() }
        status = value; epoch = UUID(); checking = false; speedTask?.cancel(); speedResult = nil
        healthTask?.cancel(); monitorTask?.cancel()
        healthy = false
        if value != .connected {
            if [.disconnected, .invalid].contains(value) { upload = 0; download = 0; uploadRate = 0; downloadRate = 0; activeServerID = nil; delays = [:]; log("VPN отключён") }
            return
        }
        if sessionStarted == nil { sessionStarted = Date(); sessionUptime = ProcessInfo.processInfo.systemUptime; traffic = TrafficMeter() }
        log("Системный туннель подключён")
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
            if !result { log("HTTPS-проверка: связи нет") }
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
                  let values = try JSONSerialization.jsonObject(with: response) as? [String: NSNumber], values["upload"] != nil, values["download"] != nil else { return }
            traffic.sample(upload: values["upload"]?.int64Value ?? 0, download: values["download"]?.int64Value ?? 0, time: ProcessInfo.processInfo.systemUptime)
            upload = traffic.upload; download = traffic.download; uploadRate = traffic.uploadRate; downloadRate = traffic.downloadRate
            if let snapshot = try await backend.routeSnapshot(), epoch == token, status == .connected, !Task.isCancelled {
                activeServerID = profile.connectionPool.first { $0.outboundTag == snapshot.active_tag }?.id
                delays = Dictionary(uniqueKeysWithValues: profile.connectionPool.compactMap { server in
                    guard let delay = snapshot.delays[server.outboundTag], (1...60_000).contains(delay) else { return nil }
                    return (server.id, delay)
                })
            }
        } catch { /* Optional counters never change real VPN status. */ }
    }
    @discardableResult func updateSubscription(_ id: String) async -> Bool {
        guard editable else { return false }
        busy = true; defer { busy = false }
        let result = await fetchSubscription(id)
        if result { notice = "Подписка обновлена" }
        return result
    }
    private func fetchSubscription(_ id: String) async -> Bool {
        guard let sub = profile.subscriptions.first(where: { $0.id == id }), let url = URL(string: sub.url) else { return false }
        let token = revision
        do {
            let text = try await subscriptionFetch(url)
            try Task.checkCancellation()
            guard foreground, !active, token == revision else { throw FoxError.invalid("VPN или профиль изменился. Повторите обновление после отключения.") }
            var copy = profile; try copy.replaceSubscription(id, content: text)
            try vault.save(copy); profile = copy; revision = UUID(); error = nil; log("Подписка обновлена"); return true
        } catch { self.error = "Не удалось обновить подписку. Сохранённый список не изменён."; log("Обновление подписки не выполнено"); return false }
    }
    func updateSubscriptions(_ ids: [String]? = nil) async {
        guard editable else { return }
        let selected = ids ?? profile.subscriptions.map(\.id)
        guard !selected.isEmpty else { return }
        busy = true; defer { busy = false }
        var count = 0
        for id in selected {
            guard !Task.isCancelled, foreground, !active else { break }
            if await fetchSubscription(id) { count += 1 }
        }
        notice = "Обновлено подписок: \(count) из \(selected.count)"
        if count != selected.count { error = "Часть подписок не обновлена. Их прежние серверы сохранены." }
    }
    func setForeground(_ value: Bool) {
        foreground = value; subscriptionTask?.cancel(); subscriptionTask = nil
        guard value else { speedTask?.cancel(); return }
        subscriptionTask = Task { [weak self] in
            while !Task.isCancelled {
                if let self {
                    guard self.foreground else { return }
                    if self.loaded && self.editable {
                    let force = !self.updatedOnLaunch && self.profile.settings.ios.update_on_launch
                    self.updatedOnLaunch = true
                    let now = Date()
                    let ids = self.profile.dueSubscriptions(now: UInt64(now.timeIntervalSince1970), force: force).filter { force || now.timeIntervalSince(self.automaticAttempts[$0] ?? .distantPast) >= 300 }
                    for id in ids { self.automaticAttempts[id] = now }
                    if !ids.isEmpty { await self.updateSubscriptions(ids) }
                    }
                } else { return }
                do { try await Task.sleep(for: .seconds(60)) } catch { return }
            }
        }
    }
    func testPool() async {
        guard status == .connected, !testingServers, !testingSpeed, !busy else { return }
        testingServers = true; let token = epoch; defer { testingServers = false }
        var copy = profile; var success = 0
        for server in profile.connectionPool {
            guard epoch == token, status == .connected, !Task.isCancelled else { return }
            do {
                let delay = try await backend.measure(tag: server.outboundTag)
                guard epoch == token, status == .connected, let index = copy.servers.firstIndex(where: { $0.id == server.id }) else { return }
                guard let delay, (1...60_000).contains(delay) else { throw FoxError.invalid("Сервер не отвечает.") }
                copy.servers[index].latency_ms = UInt64(delay); copy.servers[index].status = "available"; copy.servers[index].last_error = nil
                copy.servers[index].successes = copy.servers[index].successes == UInt64.max ? UInt64.max : copy.servers[index].successes + 1
                delays[server.id] = delay; success += 1
            } catch {
                guard epoch == token, status == .connected, let index = copy.servers.firstIndex(where: { $0.id == server.id }) else { return }
                copy.servers[index].latency_ms = nil; copy.servers[index].status = "unavailable"; copy.servers[index].last_error = "HTTPS-проверка через сервер не выполнена."
                copy.servers[index].failures = copy.servers[index].failures == UInt64.max ? UInt64.max : copy.servers[index].failures + 1
                delays.removeValue(forKey: server.id)
            }
        }
        do { try vault.save(copy); profile = copy; revision = UUID(); notice = "Ответили серверы: \(success) из \(profile.connectionPool.count)"; log("Проверка серверов завершена") }
        catch { self.error = "Результаты проверки не сохранены в Keychain." }
    }
    func startSpeedTest() { speedTask?.cancel(); speedTask = Task { [weak self] in await self?.measureSpeed() } }
    func cancelSpeedTest() { speedTask?.cancel() }
    func measureSpeed() async {
        guard status == .connected, !testingSpeed, !testingServers, !busy else { return }
        guard profile.settings.mode != .direct, (try? profile.route(for: "speed.cloudflare.com")) == "vpn" else { error = "Для измерения VPN выберите маршрут speed.cloudflare.com через VPN."; return }
        testingSpeed = true; speedResult = nil; let token = epoch; let originalServer = activeServerID; defer { testingSpeed = false }
        do {
            let result = try await speedChecker.measure()
            guard !Task.isCancelled, foreground, epoch == token, status == .connected else { return }
            guard result.downloadMbps.isFinite, result.uploadMbps.isFinite, result.downloadMbps > 0, result.uploadMbps > 0 else { throw FoxError.invalid("Измерение не завершено.") }
            speedResult = result
            // Automatic switching can use two servers during a test: then save no per-server value.
            if !profile.settings.ios.automatic_server {
                let id = originalServer ?? profile.selected
                var copy = profile
                if let index = copy.servers.firstIndex(where: { $0.id == id }) {
                    copy.servers[index].download_mbps = result.downloadMbps
                    try vault.save(copy); profile = copy; revision = UUID()
                }
            }
            notice = "Измерение приёма и отправки завершено"; log("Измерение скорости завершено")
        } catch {
            guard !Task.isCancelled, epoch == token, status == .connected else { return }
            self.error = "Не удалось завершить измерение скорости. Частичные данные не сохранены."; log("Измерение скорости не выполнено")
        }
    }
    private func finishSession() {
        defer { sessionStarted = nil; sessionUptime = nil }
        guard loaded, let start = sessionStarted, let uptime = sessionUptime else { return }
        var copy = profile
        copy.settings.ios.history.insert(TrafficSession(started: start.timeIntervalSince1970, duration: max(0, ProcessInfo.processInfo.systemUptime - uptime), upload: upload, download: download), at: 0)
        copy.settings.ios.history = Array(copy.settings.ios.history.prefix(100))
        do { try copy.validate(); try vault.save(copy); profile = copy; revision = UUID() }
        catch { log("История сеанса не сохранена") }
    }
    private func log(_ text: String) {
        // Callers supply fixed messages only: no URI, host, server name or raw system error.
        diagnostics.append(Date().formatted(date: .omitted, time: .standard) + " · " + text)
        diagnostics = Array(diagnostics.suffix(100))
    }
    func clearDiagnostics() { diagnostics = [] }
    var diagnosticReport: String { "foxVPN iOS " + AppMetadata.version + "\n" + diagnostics.joined(separator: "\n") }

}

final class MemoryProfileStore: ProfileStoring {
    private var value = VPNProfile()
    func load() throws -> VPNProfile { value }
    func save(_ profile: VPNProfile) throws { value = profile }
}
