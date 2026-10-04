import SwiftUI

struct ServerEditor: View {
    @EnvironmentObject var vpn: VPNController
    @Environment(\.dismiss) private var dismiss
    let server: VPNServer?
    @State private var draft: ServerDraft
    @State private var modalID = UUID()
    init(server: VPNServer? = nil) { self.server = server; _draft = State(initialValue: ServerDraft(server: server)) }
    var body: some View {
        NavigationStack {
            Form {
                Section("Сервер") {
                    TextField("Название", text: $draft.name).accessibilityIdentifier("serverName")
                    TextField("Группа", text: $draft.group).accessibilityIdentifier("serverGroup")
                    Toggle("Избранный", isOn: $draft.favorite)
                }
                if server == nil { connectionFields }
                else { DisclosureGroup("Параметры подключения") { connectionFields } }
                Section { Button(server == nil ? "Добавить сервер" : "Сохранить изменения") {
                    if vpn.change({ profile in
                        let value = try draft.server()
                        if let server {
                            guard let index = profile.servers.firstIndex(where: { $0.id == server.id }) else { throw FoxError.invalid("Сервер уже удалён.") }
                            profile.servers[index] = value
                        } else { profile.servers.append(value); if profile.selected == nil { profile.selected = value.id } }
                    }) { vpn.notice = "Сервер сохранён"; dismiss() }
                }.accessibilityIdentifier("serverSave").disabled(!vpn.editable || draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) }
            }.safeAreaInset(edge: .top) { InlineErrorBanner() }.navigationTitle(server == nil ? "Новый сервер" : "Редактировать сервер").navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Отмена") { dismiss() } }
        }.onAppear { vpn.beginEditingSheet(modalID) }.onDisappear { vpn.endEditingSheet(modalID) }
    }
    @ViewBuilder private var connectionFields: some View {
        TextField("Адрес", text: $draft.address).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("serverAddress")
        TextField("Порт", text: $draft.port).keyboardType(.numberPad).accessibilityIdentifier("serverPort")
        TextField("UUID", text: $draft.uuid).textInputAutocapitalization(.never).autocorrectionDisabled().accessibilityIdentifier("serverUUID")
        Picker("Транспорт", selection: $draft.transport) { Text("TCP").tag("tcp"); Text("WebSocket").tag("ws"); Text("gRPC").tag("grpc") }
        Picker("Защита", selection: $draft.security) { Text("TLS").tag("tls"); Text("Reality").tag("reality"); Text("Без TLS").tag("none") }
        TextField("SNI", text: $draft.sni).textInputAutocapitalization(.never).autocorrectionDisabled()
        if draft.security == "reality" { TextField("Public key", text: $draft.publicKey).textInputAutocapitalization(.never).autocorrectionDisabled(); TextField("Short ID", text: $draft.shortID).textInputAutocapitalization(.never).autocorrectionDisabled() }
        if draft.transport == "ws" { TextField("Путь WebSocket", text: $draft.path).textInputAutocapitalization(.never).autocorrectionDisabled(); TextField("Host", text: $draft.host).textInputAutocapitalization(.never).autocorrectionDisabled() }
        if draft.transport == "grpc" { TextField("Service name", text: $draft.service).textInputAutocapitalization(.never).autocorrectionDisabled() }
        DisclosureGroup("Дополнительно") {
            TextField("TLS fingerprint", text: $draft.fingerprint).textInputAutocapitalization(.never).autocorrectionDisabled()
            TextField("Flow", text: $draft.flow).textInputAutocapitalization(.never).autocorrectionDisabled()
            TextField("ALPN через запятую", text: $draft.alpn).textInputAutocapitalization(.never).autocorrectionDisabled()
        }
    }
}
