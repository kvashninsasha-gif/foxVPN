import SwiftUI
import UniformTypeIdentifiers
import CoreImage.CIFilterBuiltins

struct ContentView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var importSheet = false
    var body: some View {
        TabView {
            NavigationStack { overview }.tabItem { Label("Обзор", systemImage: "shield.lefthalf.filled") }
            NavigationStack { ServersView() }.tabItem { Label("Серверы", systemImage: "server.rack") }
            NavigationStack { RoutingView() }.tabItem { Label("Правила", systemImage: "arrow.triangle.branch") }
            NavigationStack { StatisticsView() }.tabItem { Label("Статистика", systemImage: "chart.bar") }
            NavigationStack { SettingsView() }.tabItem { Label("Настройки", systemImage: "gearshape") }
        }
        .safeAreaInset(edge: .top) {
            if let notice = vpn.notice {
                HStack { Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.foxOrange); Text(notice).font(.subheadline); Spacer(); Button { vpn.notice = nil } label: { Image(systemName: "xmark") }.accessibilityLabel("Закрыть уведомление") }.padding(14).background(.regularMaterial).task(id: notice) { do { try await Task.sleep(for: .seconds(5)); if !Task.isCancelled && vpn.notice == notice { vpn.notice = nil } } catch {} }
            }
        }
        .sheet(isPresented: $importSheet) { ImportView() }
        .alert("foxVPN", isPresented: Binding(get: { vpn.error != nil && !vpn.importPresented }, set: { if !$0 { Task { @MainActor in vpn.error = nil } } })) { Button("Понятно") { vpn.error = nil } } message: { Text(vpn.error ?? "") }
    }
    private var overview: some View {
        ScrollView {
            VStack(spacing: 24) {
                HStack(spacing: 14) {
                    Image("FoxIcon").resizable().scaledToFit().frame(width: 58, height: 58).clipShape(RoundedRectangle(cornerRadius: 16))
                    VStack(alignment: .leading) { Text("foxVPN").font(.system(size: 29, weight: .bold)); Text("Интернет по вашим правилам").font(.caption).foregroundStyle(.secondary) }
                    Spacer()
                }
                if !vpn.loaded && !vpn.busy {
                    VStack(spacing: 12) { Text("Сохранённый профиль не заменён").font(.headline); Text("Разблокируйте устройство и повторите загрузку.").font(.subheadline); Button("Повторить загрузку") { Task { await vpn.reload() } }.buttonStyle(.bordered) }.padding(20).frame(maxWidth: .infinity).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
                }
                VStack(spacing: 18) {
                    Image("FoxIcon").resizable().scaledToFit().frame(width: 110, height: 110).clipShape(RoundedRectangle(cornerRadius: 32)).padding(20).background(vpn.healthy ? Color.green.opacity(0.10) : Color.foxOrange.opacity(0.08), in: Circle())
                    Text(vpn.title).font(.title.bold()).accessibilityIdentifier("connectionStatus")
                    Text(vpn.profile.servers.first { $0.id == vpn.activeServerID }?.name ?? vpn.profile.selectedServer?.name ?? "Добавьте свой VPN-сервер").font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    Button {
                        if !vpn.active && vpn.profile.selectedServer == nil { importSheet = true }
                        else { Task { await vpn.toggleConnection() } }
                    } label: { Label(vpn.busy ? "Подождите…" : vpn.active ? "Отключиться" : "Подключиться", systemImage: "power").foregroundStyle(Color.foxButtonText).font(.headline).frame(maxWidth: .infinity).padding(.vertical, 8) }
                    .buttonStyle(.borderedProminent).disabled(vpn.busy || (!vpn.loaded && !vpn.active)).accessibilityIdentifier("connectButton")
                    HStack { Label("Профиль в Keychain", systemImage: "lock.fill"); Spacer(); Text("iOS " + AppMetadata.version) }.font(.caption2).foregroundStyle(.secondary)
                }.padding(24).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 28))
                VStack(alignment: .leading, spacing: 12) {
                    Text("Режим маршрутизации").font(.headline)
                    ForEach(RoutingMode.allCases) { mode in
                        Button { vpn.change { $0.settings.mode = mode } } label: {
                            HStack { Image(systemName: mode == .smart ? "bolt.fill" : mode == .direct ? "globe" : mode == .vpn ? "shield.fill" : "slider.horizontal.3").frame(width: 25); VStack(alignment: .leading, spacing: 4) { Text(mode.title).font(.subheadline.bold()); Text(mode.detail).font(.caption).foregroundStyle(Color(uiColor: .secondaryLabel)) }; Spacer(); Image(systemName: vpn.profile.settings.mode == mode ? "checkmark.circle.fill" : "circle") }.padding(14).foregroundStyle(vpn.profile.settings.mode == mode ? Color.foxOrange : Color.primary).background(vpn.profile.settings.mode == mode ? Color.foxOrange.opacity(0.08) : Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 16))
                        }.buttonStyle(.plain).disabled(!vpn.editable)
                    }
                }
                if vpn.active {
                    HStack { traffic("Отправлено", vpn.upload, "arrow.up"); Spacer(); traffic("Получено", vpn.download, "arrow.down") }.padding(20).background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
                    Button(vpn.checking ? "Проверяем интернет…" : "Проверить интернет") { Task { await vpn.checkConnection() } }.disabled(vpn.checking)
                }
                #if targetEnvironment(simulator)
                Label("Симулятор: интерфейс и настройки. VPN проверяется на настоящем iPhone.", systemImage: "iphone").font(.caption).foregroundStyle(.secondary)
                #endif
            }.padding(20)
        }.background(Color.foxCanvas).navigationTitle("Обзор").navigationBarTitleDisplayMode(.inline)
        .toolbar { Button { importSheet = true } label: { Image(systemName: "plus") }.accessibilityLabel("Добавить сервер") }

    }
    private func traffic(_ title: String, _ bytes: Int64, _ icon: String) -> some View { VStack(alignment: .leading, spacing: 6) { Label(title, systemImage: icon).font(.caption).foregroundStyle(.secondary); Text(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .binary)).font(.headline) } }
}

struct ServersView: View {
    @EnvironmentObject var vpn: VPNController
    @State private var showImport = false
    @State private var query = ""
    @State private var favoriteOnly = false
    @State private var selectedGroup = ""
    @State private var deleting: VPNServer?
    @State private var qr: VPNServer?
    @State private var editing: VPNServer?
    var body: some View {
        List {
            if vpn.profile.servers.isEmpty { VStack(spacing: 14) { Image(systemName: "server.rack").font(.largeTitle).foregroundStyle(Color.foxOrange); Text("Ваши серверы").font(.title2.bold()); Text("Вставьте VLESS-ссылку, отсканируйте QR или импортируйте профиль foxVPN с Mac.").foregroundStyle(.secondary).multilineTextAlignment(.center); Button("Добавить сервер") { showImport = true }.buttonStyle(.borderedProminent) }.padding(.vertical, 32).frame(maxWidth: .infinity).listRowBackground(Color.clear) }
            else {
                Toggle("Только избранные", isOn: $favoriteOnly)
                Picker("Группа", selection: $selectedGroup) { Text("Все группы").tag(""); ForEach(Array(Set(vpn.profile.servers.map(\.group))).sorted(), id: \.self) { Text($0).tag($0) } }
                ForEach(vpn.profile.servers.filter { (!favoriteOnly || $0.favorite) && (selectedGroup.isEmpty || $0.group == selectedGroup) && (query.isEmpty || $0.name.localizedCaseInsensitiveContains(query) || $0.group.localizedCaseInsensitiveContains(query)) }) { server in
                    Button { vpn.change { $0.selected = server.id } } label: { HStack { Image(systemName: server.favorite ? "star.fill" : "server.rack").foregroundStyle(Color.foxOrange); VStack(alignment: .leading) { Text(server.name).foregroundStyle(.primary); Text("\(server.group) · \(server.transport.uppercased()) · \(server.security.uppercased())").font(.caption).foregroundStyle(.secondary); if let delay = vpn.delays[server.id] { Text("Сейчас: \(delay) мс").font(.caption).foregroundStyle(Color.foxOrange) } else if let delay = server.latency_ms { Text("Последний тест: \(delay) мс").font(.caption).foregroundStyle(.secondary) } }; Spacer(); if vpn.profile.selected == server.id { Image(systemName: "checkmark.circle.fill") } } }.disabled(!vpn.editable)
                    .contextMenu { Button(server.favorite ? "Убрать из избранного" : "В избранное") { vpn.change { p in let i = p.servers.firstIndex { $0.id == server.id }; if let i { p.servers[i].favorite.toggle() } } }.disabled(!vpn.editable); Button("Редактировать") { editing = server }.disabled(!vpn.editable); Button("Показать QR") { qr = server }; ShareLink(item: server.uri()) { Label("Поделиться ссылкой", systemImage: "square.and.arrow.up") }; Button("Удалить", role: .destructive) { deleting = server }.disabled(!vpn.editable) }
                }
            }
        }.searchable(text: $query, prompt: "Имя или группа").navigationTitle("Серверы")
        .toolbar { Button { showImport = true } label: { Image(systemName: "plus") }.accessibilityLabel("Добавить сервер") }
        .sheet(isPresented: $showImport) { ImportView() }.sheet(item: $qr) { QRView(server: $0) }.sheet(item: $editing) { ServerEditor(server: $0) }
        .confirmationDialog("Удалить сервер?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) { Button("Удалить", role: .destructive) { if let deleting { vpn.change { p in p.servers.removeAll { $0.id == deleting.id }; if p.selected == deleting.id { p.selected = p.servers.first?.id } } }; deleting = nil } }
    }
}

struct ImportView: View {
    @EnvironmentObject var vpn: VPNController
    @Environment(\.dismiss) var dismiss
    @State private var text = ""
    @State private var file = false
    @State private var scanner = false
    @State private var manual = false
    @State private var qrFile = false
    @State private var imageTask: Task<Void, Never>?
    @State private var modalID = UUID()
    @State private var pendingProfile: Data?
    var body: some View {
        NavigationStack {
            Form {
                Section("VLESS-ссылки") { TextEditor(text: $text).frame(minHeight: 150).autocorrectionDisabled().textInputAutocapitalization(.never).accessibilityIdentifier("importText"); PasteButton(payloadType: String.self) { values in text = values.joined(separator: "\n") }; Button("Сканировать QR", systemImage: "qrcode.viewfinder") { scanner = true }.disabled(!vpn.editable) }
                Section { Button("Добавить вручную") { manual = true }.disabled(!vpn.editable); Button("QR из изображения") { qrFile = true }.disabled(!vpn.editable); Button("Импортировать ссылки") { vpn.importLinks(text); if vpn.error == nil { dismiss() } }.disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !vpn.editable); Button("Импортировать файл с Mac") { file = true }.disabled(!vpn.editable) } footer: { Text("JSON-профиль foxVPN или текстовый файл с VLESS-ссылками. Профиль с Mac содержит ключи доступа: передавайте его только себе. Импорт JSON заменяет текущий профиль.") }
            }.safeAreaInset(edge: .top) { InlineErrorBanner() }.navigationTitle("Добавить сервер").toolbar { Button("Закрыть") { dismiss() } }
            .fileImporter(isPresented: $file, allowedContentTypes: [.json, .plainText]) { result in
                do { let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }; let attrs = try url.resourceValues(forKeys: [.fileSizeKey]); guard (attrs.fileSize ?? 0) <= 4_000_000 else { throw FoxError.invalid("Файл слишком большой.") }; let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }; let data = try handle.read(upToCount: 4_000_001) ?? Data(); let value = try ProfileImport.parse(data); let isJSON: Bool; if case .profile = value { isJSON = true } else { isJSON = false }; if isJSON && (!vpn.profile.servers.isEmpty || !vpn.profile.rules.isEmpty || !vpn.profile.subscriptions.isEmpty) { pendingProfile = data } else { vpn.importFile(data); if vpn.error == nil { dismiss() } } } catch { if (error as NSError).code != NSUserCancelledError { vpn.error = (error as? FoxError)?.localizedDescription ?? "Не удалось прочитать файл профиля." } }
            }.confirmationDialog("Заменить текущий профиль?", isPresented: Binding(get: { pendingProfile != nil }, set: { if !$0 { pendingProfile = nil } }), titleVisibility: .visible) { Button("Заменить профиль", role: .destructive) { if let data = pendingProfile { vpn.importFile(data); if vpn.error == nil { dismiss() } }; pendingProfile = nil }; Button("Отмена", role: .cancel) { pendingProfile = nil } } message: { Text("Серверы, правила и настройки будут заменены данными из файла.") }.sheet(isPresented: $scanner) { QRScanner { value in text = value; scanner = false } }.sheet(isPresented: $manual) { ServerEditor() }
            .fileImporter(isPresented: $qrFile, allowedContentTypes: [.image]) { result in
                do {
                    let url = try result.get(); let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0; guard size <= 20_000_000 else { throw FoxError.invalid("Изображение слишком большое.") }
                    let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }; let data = try handle.read(upToCount: 20_000_001) ?? Data()
                    imageTask?.cancel()
                    imageTask = Task {
                        do { let links = try await Task.detached(priority: .userInitiated) { try QRImageReader.links(from: data) }.value; guard !Task.isCancelled else { return }; text = links; vpn.error = nil }
                        catch { if !Task.isCancelled { vpn.error = (error as? FoxError)?.localizedDescription ?? "Не удалось прочитать QR." } }
                    }
                } catch { if (error as NSError).code != NSUserCancelledError { vpn.error = error.localizedDescription } }
            }
        }.onAppear { vpn.beginEditingSheet(modalID) }
        .onDisappear { imageTask?.cancel(); vpn.endEditingSheet(modalID) }
    }
}

struct QRView: View {
    let server: VPNServer
    @Environment(\.dismiss) var dismiss
    private var image: UIImage? { let filter = CIFilter.qrCodeGenerator(); filter.message = Data(server.uri().utf8); guard let output = filter.outputImage?.transformed(by: .init(scaleX: 8, y: 8)), let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }; return UIImage(cgImage: cg) }
    var body: some View { NavigationStack { VStack(spacing: 24) { Text(server.name).font(.title2.bold()); if let image { Image(uiImage: image).interpolation(.none).resizable().scaledToFit().padding(20).background(.white).clipShape(RoundedRectangle(cornerRadius: 20)).frame(maxWidth: 340) } else { Label("Ссылка слишком длинная для QR. Используйте передачу ссылки.", systemImage: "exclamationmark.circle").foregroundStyle(.secondary) }; Text("QR содержит ключ доступа. Передавайте его только доверенным устройствам.").font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center); ShareLink(item: server.uri()) { Label("Передать ссылку", systemImage: "square.and.arrow.up") } }.padding(24).navigationTitle("QR сервера").toolbar { Button("Готово") { dismiss() } } } }
}
