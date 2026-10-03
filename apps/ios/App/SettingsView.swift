import SwiftUI

struct RoutingView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var domain = ""
    @State private var route = "vpn"
    @State private var check = ""
    @State private var result: String?
    var body: some View {
        Form {
            Section("Новое правило") {
                TextField("example.com или *.example.com", text: $domain).autocorrectionDisabled().textInputAutocapitalization(.never).accessibilityIdentifier("ruleDomain")
                Picker("Маршрут", selection: $route) { Text("Через VPN").tag("vpn"); Text("Напрямую").tag("direct") }
                Button("Добавить правило") { vpn.change { p in p.rules.append(try DomainRule(domain: domain, route: route).normalized()) }; if vpn.error == nil { domain = "" } }.disabled(!vpn.editable || domain.isEmpty)
            }
            Section("Исключения") { ForEach(vpn.profile.rules) { rule in HStack { Text(rule.domain); Spacer(); Text(rule.route == "vpn" ? "VPN" : "Напрямую").foregroundStyle(.secondary) } }.onDelete { indices in vpn.change { $0.rules.remove(atOffsets: indices) } } }
            Section { TextField("Домен сайта", text: $check).autocorrectionDisabled().textInputAutocapitalization(.never); Button("Проверить маршрут") { do { result = try vpn.profile.route(for: check) == "vpn" ? "Через VPN" : "Напрямую" } catch { vpn.error = error.localizedDescription } }; if let result { Text(result).foregroundStyle(Color.foxOrange) } } header: { Text("Проверить правило") } footer: { Text("Проверяется правило маршрутизации. Это не сетевой запрос и не тест доступности сайта.") }
        }.navigationTitle("Маршрутизация")
    }
}

struct SettingsView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var subscriptionName = ""
    @State private var subscriptionURL = ""
    private func setting<T>(_ key: WritableKeyPath<VPNSettings, T>) -> Binding<T> { Binding(get: { vpn.profile.settings[keyPath: key] }, set: { value in vpn.change { $0.settings[keyPath: key] = value } }) }
    var body: some View {
        Form {
            Section {
                Toggle("Подключаться по требованию", isOn: setting(\.auto_connect)).disabled(!vpn.editable)
                Toggle("Охватывать все сети", isOn: setting(\.include_all_networks)).disabled(!vpn.editable)
            } header: { Text("Подключение") } footer: { Text("iOS управляет VPN в фоне. Охват всех сетей использует системную политику iOS; её защита при сбоях ещё требует проверки на вашем iPhone. Явное отключение отменяет подключение по требованию до следующего подключения.") }
            Section("DNS") {
                Picker("Провайдер", selection: setting(\.dns_provider)) { Text("Cloudflare").tag("cloudflare"); Text("Google").tag("google"); Text("Quad9").tag("quad9") }.disabled(!vpn.editable)
                Picker("Защита DNS", selection: setting(\.dns_transport)) { Text("DNS over HTTPS").tag("https"); Text("DNS over TLS").tag("tls"); Text("Системный DNS").tag("local") }.disabled(!vpn.editable)
            }
            Section("Подписки") {
                ForEach(vpn.profile.subscriptions) { sub in VStack(alignment: .leading, spacing: 8) { Text(sub.name).font(.headline); HStack { Button("Обновить") { Task { await vpn.updateSubscription(sub.id) } }.disabled(!vpn.editable); Spacer(); Button("Удалить", role: .destructive) { vpn.change { $0.subscriptions.removeAll { $0.id == sub.id } } }.disabled(!vpn.editable) } } }
                TextField("Название", text: $subscriptionName)
                TextField("https://…", text: $subscriptionURL).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Добавить подписку") { vpn.change { $0.subscriptions.append(VPNSubscription(name: subscriptionName, url: subscriptionURL)) }; if vpn.error == nil { subscriptionName = ""; subscriptionURL = "" } }.disabled(!vpn.editable || subscriptionName.isEmpty || subscriptionURL.isEmpty)
            }
            Section("О приложении") { LabeledContent("Версия", value: "0.1.0 для iPhone"); LabeledContent("Ядро", value: "sing-box 1.14.2"); Label("Профиль хранится в Keychain устройства", systemImage: "lock.shield"); Link("Исходники и обновления", destination: URL(string: "https://github.com/kvashninsasha-gif/smart-vpn-router")!) }
        }.navigationTitle("Настройки")
    }
}
