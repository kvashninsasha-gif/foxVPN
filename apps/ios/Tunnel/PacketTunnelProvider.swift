import Foundation
import NetworkExtension
import Libbox
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let workQueue = DispatchQueue(label: "foxVPN.tunnel.lifecycle")
    private var engine: LibboxCommandServer?
    private var platform: TunnelPlatform?
    private var apiSecret = ""
    private var apiPort: UInt16 = 0
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        workQueue.async {
            do {
                let profile = try ProfileVault().load(); try profile.validate()
                guard profile.selectedServer != nil else { throw FoxError.noServer }
                guard let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup) else { throw FoxError.storage }
                var working = root.appendingPathComponent("Network", isDirectory: true)
                try FileManager.default.createDirectory(at: working, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
                var resourceValues = URLResourceValues(); resourceValues.isExcludedFromBackup = true; try working.setResourceValues(resourceValues)
                let temp = working.appendingPathComponent("Temp", isDirectory: true)
                try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
                self.apiSecret = UUID().uuidString + UUID().uuidString; self.apiPort = try Self.freePort()
                let setup = LibboxSetupOptions(); setup.basePath = working.path; setup.workingPath = working.path; setup.tempPath = temp.path
                setup.commandServerSecret = UUID().uuidString; setup.logMaxLines = 0; setup.debug = false; setup.oomKillerEnabled = true; setup.oomMemoryLimit = 40 * 1024 * 1024; setup.appVersion = "1"; setup.appMarketingVersion = "0.1.0"; setup.crashReportSource = "foxVPN"
                var failure: NSError?
                guard LibboxSetup(setup, &failure), failure == nil else { throw failure ?? FoxError.storage as NSError }
                let config = try TunnelConfiguration.make(profile: profile, apiPort: Int(self.apiPort), secret: self.apiSecret)
                guard LibboxCheckConfig(config, &failure), failure == nil else { throw failure ?? FoxError.invalid("Конфигурация VPN отклонена ядром.") as NSError }
                let bridge = TunnelPlatform(provider: self); self.platform = bridge
                guard let core = LibboxNewCommandServer(bridge, bridge, &failure), failure == nil else { throw failure ?? FoxError.invalid("Не удалось создать VPN-ядро.") as NSError }
                self.engine = core
                // No public gRPC listener is needed: app control is NE provider messaging.
                try core.startOrReloadService(config, options: LibboxOverrideOptions())
                try self.removeConfigSnapshot(working)
                completionHandler(nil)
            } catch {
                self.engine?.close(); self.engine = nil; self.platform?.shutdown(); self.platform = nil
                completionHandler(FoxError.invalid("VPN не запущен. Проверьте профиль, сетевое расширение и доступ к Keychain."))
            }
        }
    }
    private func removeConfigSnapshot(_ working: URL) throws {
        let snapshot = working.appendingPathComponent("configuration.json")
        if FileManager.default.fileExists(atPath: snapshot.path) { try FileManager.default.removeItem(at: snapshot) }
    }
    static var appGroup: String { Bundle.main.object(forInfoDictionaryKey: "FoxAppGroup") as? String ?? "group.ru.smartvpn.router.ios" }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        workQueue.async { self.engine?.close(); self.engine = nil; self.platform?.shutdown(); self.platform = nil; self.apiSecret = ""; self.apiPort = 0; self.setTunnelNetworkSettings(nil) { _ in completionHandler() } }
    }
    override func sleep(completionHandler: @escaping () -> Void) { workQueue.async { self.engine?.pause(); completionHandler() } }
    override func wake() { workQueue.async { self.engine?.wake() } }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard messageData == Data("stats".utf8), apiPort != 0 else { completionHandler?(nil); return }
        var request = URLRequest(url: URL(string: "http://127.0.0.1:\(apiPort)/connections")!); request.setValue("Bearer \(apiSecret)", forHTTPHeaderField: "Authorization"); request.timeoutInterval = 2
        let session = URLSession(configuration: .ephemeral)
        session.dataTask(with: request) { data, response, _ in
            defer { session.finishTasksAndInvalidate() }
            guard (response as? HTTPURLResponse)?.statusCode == 200, let data, let result = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { completionHandler?(nil); return }
            // Never return connection hosts, config, secrets or log lines to UI.
            let safe = ["upload": result["uploadTotal"] as? Int64 ?? 0, "download": result["downloadTotal"] as? Int64 ?? 0]
            completionHandler?(try? JSONSerialization.data(withJSONObject: safe))
        }.resume()
    }
    private static func freePort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0); guard fd >= 0 else { throw FoxError.storage }; defer { close(fd) }
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0 else { throw FoxError.storage }; var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &address, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }) == 0 else { throw FoxError.storage }
        return UInt16(bigEndian: address.sin_port)
    }
}
