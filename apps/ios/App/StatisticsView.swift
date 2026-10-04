import SwiftUI

struct StatisticsView: View {
    @EnvironmentObject var vpn: VPNController
    var body: some View {
        List {
            Section("Текущий сеанс") {
                LabeledContent("Состояние", value: vpn.title)
                LabeledContent("Отправлено", value: bytes(vpn.upload))
                LabeledContent("Получено", value: bytes(vpn.download))
                LabeledContent("Отправка сейчас", value: bytes(Int64(min(Double(Int64.max - 1024), vpn.uploadRate))) + "/с")
                LabeledContent("Приём сейчас", value: bytes(Int64(min(Double(Int64.max - 1024), vpn.downloadRate))) + "/с")
                Text("Счётчики ядра включают VPN и прямые маршруты туннеля. Скорость рассчитывается по разнице счётчиков; после паузы приложения новое измерение начинается заново.").font(.caption).foregroundStyle(.secondary)
            }
            Section {
                Button(vpn.testingServers ? "Проверяем серверы…" : "Проверить серверы подключения") { Task { await vpn.testPool() } }.disabled(vpn.status != .connected || vpn.testingServers || vpn.busy)
                ForEach(vpn.profile.connectionPool) { server in
                    HStack { Text(server.name); Spacer(); if let delay = vpn.delays[server.id] { Text("\(delay) мс").foregroundStyle(Color.foxOrange) } else { Text("Нет текущего измерения").font(.caption).foregroundStyle(.secondary) } }
                }
            } header: { Text("Качество связи") } footer: { Text("После подключения ядро проверяет HTTPS через каждый сервер текущего набора. Проверка не выключает VPN. В режиме «Напрямую» она проверяет резервный VPN-сервер отдельно от прямого маршрута.") }
            Section {
                Button(vpn.testingSpeed ? "Измеряем скорость…" : "Измерить приём и отправку · 6 МБ") { vpn.startSpeedTest() }.disabled(vpn.status != .connected || vpn.testingSpeed || vpn.testingServers || vpn.busy)
                if vpn.testingSpeed { Button("Отменить измерение") { vpn.cancelSpeedTest() } }
                if let result = vpn.speedResult {
                    LabeledContent("Приём", value: String(format: "%.1f Мбит/с", result.downloadMbps))
                    LabeledContent("Отправка", value: String(format: "%.1f Мбит/с", result.uploadMbps))
                }
            } header: { Text("Быстрый тест скорости") } footer: { Text("Скачивает 5 МБ и отправляет 1 МБ в Cloudflare через текущий маршрут VPN. Cloudflare видит адрес выхода. Это быстрая оценка с учётом установки HTTPS-соединения, а не максимальная пропускная способность. Служебный трафик не входит в 6 МБ.") }
            Section("История сеансов") {
                if vpn.profile.settings.ios.history.isEmpty { Text("Здесь появятся завершённые сеансы").foregroundStyle(.secondary) }
                ForEach(vpn.profile.settings.ios.history) { item in
                    VStack(alignment: .leading, spacing: 5) { Text(Date(timeIntervalSince1970: item.started).formatted(date: .abbreviated, time: .shortened)); Text("↑ \(bytes(item.upload)) · ↓ \(bytes(item.download)) · \(Int(item.duration / 60)) мин").font(.caption).foregroundStyle(.secondary) }
                }
                Button("Очистить историю", role: .destructive) { _ = vpn.change { $0.settings.ios.history = [] } }.disabled(!vpn.editable || vpn.profile.settings.ios.history.isEmpty)
            }
            Section {
                ForEach(Array(vpn.diagnostics.enumerated()), id: \.offset) { item in Text(item.element).font(.caption).textSelection(.enabled) }
                ShareLink(item: vpn.diagnosticReport) { Label("Передать отчёт", systemImage: "square.and.arrow.up") }
                Button("Очистить журнал") { vpn.clearDiagnostics() }.disabled(vpn.diagnostics.isEmpty)
            } header: { Text("Диагностика") } footer: { Text("До 100 событий приложения, без имён серверов, адресов, UUID и ключей. Журнал хранится только в памяти и передаётся по вашей команде.") }
        }.navigationTitle("Статистика").navigationBarTitleDisplayMode(.inline)
    }
    private func bytes(_ value: Int64) -> String { ByteCountFormatter.string(fromByteCount: max(0, value), countStyle: .binary) }
}

struct SubscriptionEditor: View {
    @EnvironmentObject var vpn: VPNController
    @Environment(\.dismiss) private var dismiss
    let subscription: VPNSubscription
    @State private var name: String
    @State private var url: String
    @State private var modalID = UUID()
    init(subscription: VPNSubscription) { self.subscription = subscription; _name = State(initialValue: subscription.name); _url = State(initialValue: subscription.url) }
    var body: some View {
        NavigationStack {
            Form {
                TextField("Название", text: $name).accessibilityIdentifier("subscriptionEditName")
                TextField("https://…", text: $url).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Сохранить подписку") {
                    if vpn.change({ profile in
                        guard let index = profile.subscriptions.firstIndex(where: { $0.id == subscription.id }) else { throw FoxError.invalid("Подписка уже удалена.") }
                        let value = url.trimmingCharacters(in: .whitespacesAndNewlines)
                        if profile.subscriptions[index].url != value { profile.subscriptions[index].updated_at = nil }
                        profile.subscriptions[index].name = name.trimmingCharacters(in: .whitespacesAndNewlines); profile.subscriptions[index].url = value
                    }) { vpn.notice = "Подписка сохранена"; dismiss() }
                }.disabled(!vpn.editable)
                Text("Изменение адреса не удаляет серверы. Они заменяются только после успешного обновления.").font(.caption).foregroundStyle(.secondary)
            }.safeAreaInset(edge: .top) { InlineErrorBanner() }.navigationTitle("Изменить подписку").navigationBarTitleDisplayMode(.inline).toolbar { Button("Отмена") { dismiss() } }
        }.onAppear { vpn.beginEditingSheet(modalID) }.onDisappear { vpn.endEditingSheet(modalID) }
    }
}
