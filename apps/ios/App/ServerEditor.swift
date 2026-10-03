import SwiftUI

struct ServerEditor: View {
    @EnvironmentObject var vpn: VPNController
    @Environment(\.dismiss) private var dismiss
    let server: VPNServer
    @State private var name: String
    @State private var group: String
    @State private var favorite: Bool
    init(server: VPNServer) { self.server = server; _name = State(initialValue: server.name); _group = State(initialValue: server.group); _favorite = State(initialValue: server.favorite) }
    var body: some View {
        NavigationStack {
            Form {
                if let error = vpn.error { Section { Label(error, systemImage: "exclamationmark.circle").foregroundStyle(.red) } }
                Section("Сервер") {
                    TextField("Название", text: $name).accessibilityIdentifier("serverName")
                    TextField("Группа", text: $group).accessibilityIdentifier("serverGroup")
                    Toggle("Избранный", isOn: $favorite)
                    LabeledContent("Протокол", value: "VLESS / \(server.transport.uppercased())")
                    LabeledContent("Защита", value: server.security.uppercased())
                }
                Section { Button("Сохранить изменения") {
                    if vpn.change({ profile in
                        guard let i = profile.servers.firstIndex(where: { $0.id == server.id }) else { throw FoxError.invalid("Сервер уже удалён.") }
                        profile.servers[i].name = name.trimmingCharacters(in: .whitespacesAndNewlines)
                        profile.servers[i].group = group.trimmingCharacters(in: .whitespacesAndNewlines)
                        profile.servers[i].favorite = favorite
                    }) { vpn.notice = "Сервер сохранён"; dismiss() }
                }.disabled(!vpn.editable || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) }
            }.navigationTitle("Редактировать сервер").navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Отмена") { dismiss() } }
        }.onAppear { vpn.importPresented = true; vpn.error = nil }
        .onDisappear { vpn.importPresented = false; vpn.error = nil }
    }
}
