import SwiftUI

struct RoutingView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var domain = ""
    @State private var route = "vpn"
    @State private var check = ""
    @State private var result: String?
    @State private var editing: DomainRule?
    var body: some View {
        Form {
            Section("Новое правило") {
                TextField("example.com или *.example.com", text: $domain).autocorrectionDisabled().textInputAutocapitalization(.never).accessibilityIdentifier("ruleDomain")
                Picker("Маршрут", selection: $route) { Text("Через VPN").tag("vpn"); Text("Напрямую").tag("direct") }
                Button("Добавить правило") {
                    if vpn.change({ $0.rules.append(try DomainRule(domain: domain, route: route).normalized()) }) { domain = ""; vpn.notice = "Правило добавлено" }
                }.disabled(!vpn.editable || domain.isEmpty)
            }
            Section {
                ForEach(vpn.profile.rules) { rule in
                    Button { editing = rule } label: { HStack { Text(rule.domain).foregroundStyle(.primary); Spacer(); Text(rule.route == "vpn" ? "VPN" : "Напрямую").foregroundStyle(.secondary) } }.disabled(!vpn.editable)
                }.onDelete { indices in _ = vpn.change { $0.rules.remove(atOffsets: indices) } }
                .onMove { source, destination in _ = vpn.change { $0.rules.move(fromOffsets: source, toOffset: destination) } }
                .deleteDisabled(!vpn.editable).moveDisabled(!vpn.editable)
            } header: { Text("Исключения") } footer: { Text("Первое совпавшее правило имеет приоритет. Нажмите правило для изменения; «Править» меняет порядок.") }
            Section {
                TextField("Домен сайта", text: $check).autocorrectionDisabled().textInputAutocapitalization(.never)
                Button("Проверить маршрут") { do { result = try vpn.profile.route(for: check) == "vpn" ? "Через VPN" : "Напрямую" } catch { vpn.error = error.localizedDescription } }.disabled(check.isEmpty)
                if let result { Text(result).foregroundStyle(Color.foxOrange) }
            } header: { Text("Проверить правило") } footer: { Text("Проверяется правило маршрутизации. Это не сетевой запрос и не тест доступности сайта.") }
        }.navigationTitle("Маршрутизация").navigationBarTitleDisplayMode(.inline)
        .toolbar { EditButton().disabled(!vpn.editable || vpn.profile.rules.isEmpty) }
        .sheet(item: $editing) { RuleEditor(rule: $0) }
    }
}
struct RuleEditor: View {
    @EnvironmentObject var vpn: VPNController
    @Environment(\.dismiss) private var dismiss
    @State private var modalID = UUID()
    let rule: DomainRule
    @State private var domain: String
    @State private var route: String
    init(rule: DomainRule) { self.rule = rule; _domain = State(initialValue: rule.domain); _route = State(initialValue: rule.route) }
    var body: some View {
        NavigationStack {
            Form {
                TextField("Домен или *.домен", text: $domain).autocorrectionDisabled().textInputAutocapitalization(.never)
                Picker("Маршрут", selection: $route) { Text("Через VPN").tag("vpn"); Text("Напрямую").tag("direct") }
                Button("Сохранить правило") {
                    if vpn.change({ p in
                        guard let index = p.rules.firstIndex(where: { $0.id == rule.id }) else { throw FoxError.invalid("Правило уже удалено.") }
                        p.rules[index] = try DomainRule(domain: domain, route: route).normalized()
                    }) { vpn.notice = "Правило сохранено"; dismiss() }
                }.disabled(!vpn.editable || domain.isEmpty)
            }.safeAreaInset(edge: .top) { InlineErrorBanner() }.navigationTitle("Редактировать правило").navigationBarTitleDisplayMode(.inline).toolbar { Button("Отмена") { dismiss() } }
        }.onAppear { vpn.beginEditingSheet(modalID) }.onDisappear { vpn.endEditingSheet(modalID) }
    }
}

struct SettingsView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var subscriptionName = ""
    @State private var subscriptionURL = ""
    @State private var editingSubscription: VPNSubscription?
    @State private var removing: VPNSubscription?
    @State private var exportWarning = false
    @State private var exportFile = false
    @State private var document = ProfileDocument()
    private func setting<T>(_ key: WritableKeyPath<VPNSettings, T>) -> Binding<T> { Binding(get: { vpn.profile.settings[keyPath: key] }, set: { value in _ = vpn.change { $0.settings[keyPath: key] = value } }) }
    var body: some View {
        Form {
            Section {
                Toggle("Подключаться по требованию", isOn: setting(\.auto_connect)).disabled(!vpn.editable)
                Toggle("Охватывать все сети", isOn: setting(\.include_all_networks)).disabled(!vpn.editable)
            } header: { Text("Подключение") } footer: { Text("iOS управляет VPN в фоне. Охват всех сетей использует системную политику iOS; её защита при сбоях ещё требует проверки на вашем iPhone. Явное отключение отменяет подключение по требованию до следующего подключения.") }
            Section {
                Toggle("Автоматический выбор сервера", isOn: setting(\.ios.automatic_server)).disabled(!vpn.editable)
                Toggle("Резервы только из избранных", isOn: setting(\.ios.favorites_only)).disabled(!vpn.editable || !vpn.profile.settings.ios.automatic_server)
                Picker("Группа резервов", selection: setting(\.ios.server_group)) {
                    Text("Все группы").tag("")
                    ForEach(Array(Set(vpn.profile.servers.map(\.group) + (vpn.profile.settings.ios.server_group.isEmpty ? [] : [vpn.profile.settings.ios.server_group]))).sorted(), id: \.self) { Text($0).tag($0) }
                }.disabled(!vpn.editable || !vpn.profile.settings.ios.automatic_server)
                LabeledContent("Серверов в наборе", value: String(vpn.profile.connectionPool.count))
            } header: { Text("Автоматический выбор") } footer: { Text("Выбранный сервер и до 7 резервов. Ядро проверяет их каждую минуту и выбирает доступный с лучшим временем ответа. Переключение происходит внутри того же туннеля; существующее соединение сайта может потребовать повторного открытия.") }
            Section("DNS") {
                Picker("Провайдер", selection: setting(\.dns_provider)) { Text("Cloudflare").tag("cloudflare"); Text("Google").tag("google"); Text("Quad9").tag("quad9") }.disabled(!vpn.editable)
                Picker("Защита DNS", selection: setting(\.dns_transport)) { Text("DNS over HTTPS").tag("https"); Text("DNS over TLS").tag("tls"); Text("Системный DNS").tag("local") }.disabled(!vpn.editable)
            }
            Section("Обновление подписок") {
                Toggle("Обновлять при запуске", isOn: setting(\.ios.update_on_launch)).disabled(!vpn.editable)
                Picker("Интервал", selection: setting(\.ios.subscription_hours)) { Text("Вручную").tag(0); Text("Каждый час").tag(1); Text("6 часов").tag(6); Text("12 часов").tag(12); Text("24 часа").tag(24) }.disabled(!vpn.editable)
                Button(vpn.busy ? "Подождите…" : "Обновить все подписки") { Task { await vpn.updateSubscriptions() } }.disabled(!vpn.editable || vpn.profile.subscriptions.isEmpty)
                Text("Автоматическое обновление выполняется, пока приложение открыто и VPN отключён. iOS не гарантирует запуск закрытого приложения по расписанию.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Подписки") {
                ForEach(vpn.profile.subscriptions) { sub in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(sub.name).font(.headline)
                        if let time = sub.updated_at { Text("Обновлено: " + Date(timeIntervalSince1970: Double(time)).formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary) }
                        HStack { Button("Изменить") { editingSubscription = sub }.disabled(!vpn.editable); Button("Обновить") { Task { await vpn.updateSubscription(sub.id) } }.disabled(!vpn.editable); Spacer(); Button("Удалить", role: .destructive) { removing = sub }.disabled(!vpn.editable) }.buttonStyle(.borderless)
                    }
                }
                TextField("Название", text: $subscriptionName).accessibilityIdentifier("subscriptionName")
                TextField("https://…", text: $subscriptionURL).accessibilityIdentifier("subscriptionURL").keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Добавить подписку") {
                    if vpn.change({ $0.subscriptions.append(VPNSubscription(name: subscriptionName.trimmingCharacters(in: .whitespacesAndNewlines), url: subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines))) }) { subscriptionName = ""; subscriptionURL = ""; vpn.notice = "Подписка добавлена" }
                }.disabled(!vpn.editable || subscriptionName.isEmpty || subscriptionURL.isEmpty)
            }
            Section {
                Button("Экспортировать резервную копию") { exportWarning = true }.disabled(!vpn.loaded || vpn.busy)
            } header: { Text("Резервная копия") } footer: { Text("JSON переносится между iPhone и foxVPN на Mac. Файл содержит ключи VPN-серверов. Выбирайте своё защищённое место хранения.") }
            Section("О приложении") {
                LabeledContent("Версия", value: AppMetadata.version + " для iPhone")
                LabeledContent("Ядро", value: "sing-box 1.14.2")
                Label("Профиль хранится в Keychain устройства", systemImage: "lock.shield")
                Link("Исходники и обновления", destination: URL(string: "https://github.com/kvashninsasha-gif/smart-vpn-router")!)
            }
        }.navigationTitle("Настройки")
        .sheet(item: $editingSubscription) { SubscriptionEditor(subscription: $0) }
        .confirmationDialog("Удалить подписку?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Удалить подписку, оставить серверы") { removeSubscription(false) }
            Button("Удалить вместе с серверами", role: .destructive) { removeSubscription(true) }
            Button("Отмена", role: .cancel) { removing = nil }
        }
        .alert("Экспорт содержит ключи доступа", isPresented: $exportWarning) {
            Button("Выбрать место сохранения") { do { document = ProfileDocument(data: try vpn.profile.exportData()); exportFile = true } catch { vpn.error = error.localizedDescription } }
            Button("Отмена", role: .cancel) {}
        } message: { Text("Храните файл у себя и передавайте только своим устройствам.") }
        .fileExporter(isPresented: $exportFile, document: document, contentType: .json, defaultFilename: "foxVPN-profile") { result in
            document = ProfileDocument()
            switch result {
            case .success: vpn.notice = "Резервная копия сохранена"
            case .failure(let error): if (error as NSError).code != NSUserCancelledError { vpn.error = "Не удалось сохранить резервную копию." }
            }
        }
    }
    private func removeSubscription(_ servers: Bool) {
        if let removing { if vpn.change({ $0.removeSubscription(removing.id, removeServers: servers) }) { vpn.notice = "Подписка удалена" } }
        removing = nil
    }
}
