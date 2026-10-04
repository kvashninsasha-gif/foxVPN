import Foundation

public struct IOSPreferences: Codable {
    public var automatic_server = false
    public var favorites_only = false
    public var server_group = ""
    public var update_on_launch = false
    public var subscription_hours = 0
    public var history: [TrafficSession] = []
    public init() {}
    public func validate() throws {
        guard [0, 1, 6, 12, 24].contains(subscription_hours), server_group.count <= 200,
              !server_group.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }), history.count <= 100,
              history.allSatisfy({ $0.upload >= 0 && $0.download >= 0 && $0.duration.isFinite && $0.duration >= 0 && $0.duration <= 31_536_000 && $0.started >= 0 && $0.started <= 32_503_680_000 }) else { throw FoxError.invalid("Некорректные настройки iPhone или история трафика.") }
    }
}
public struct TrafficSession: Codable, Identifiable {
    public var id: String
    public var started: Double
    public var duration: Double
    public var upload: Int64
    public var download: Int64
    public init(started: Double, duration: Double, upload: Int64, download: Int64) {
        id = UUID().uuidString; self.started = started; self.duration = duration; self.upload = upload; self.download = download
    }
}
public struct TrafficMeter {
    public private(set) var uploadRate = 0.0
    public private(set) var downloadRate = 0.0
    public private(set) var upload: Int64 = 0
    public private(set) var download: Int64 = 0
    private var previous: (time: Double, upload: Int64, download: Int64)?
    private var uploadOffset: Int64 = 0
    private var downloadOffset: Int64 = 0
    public init() {}
    public mutating func sample(upload: Int64, download: Int64, time: Double) {
        guard time.isFinite else { return }
        let up = max(0, upload), down = max(0, download)
        if let old = previous {
            guard time > old.time else { return }
            if up < old.upload { uploadOffset = self.upload }
            if down < old.download { downloadOffset = self.download }
            // A long gap (suspension) has no meaningful instantaneous speed.
            let elapsed = time - old.time
            uploadRate = elapsed <= 15 && up >= old.upload ? Double(up - old.upload) / elapsed : 0
            downloadRate = elapsed <= 15 && down >= old.download ? Double(down - old.download) / elapsed : 0
        }
        self.upload = uploadOffset.addingReportingOverflow(up).overflow ? Int64.max : uploadOffset + up
        self.download = downloadOffset.addingReportingOverflow(down).overflow ? Int64.max : downloadOffset + down
        previous = (time, up, down)
    }
}
public struct TunnelRouteSnapshot: Codable {
    public var active_tag: String?
    public var delays: [String: Int]
    public init(active_tag: String?, delays: [String: Int]) { self.active_tag = active_tag; self.delays = delays }
}
extension VPNProfile {
    public static let maximumAutomaticServers = 8
    public var connectionPool: [VPNServer] {
        guard let selectedServer else { return [] }
        guard settings.ios.automatic_server, settings.mode != .direct else { return [selectedServer] }
        let candidates = servers.filter { (!settings.ios.favorites_only || $0.favorite) && (settings.ios.server_group.isEmpty || $0.group == settings.ios.server_group) }
        // Manual choice remains the initial server; only qualifying alternatives are reserves.
        return [selectedServer] + Array(candidates.filter { $0.id != selectedServer.id }.prefix(Self.maximumAutomaticServers - 1))
    }
    public func dueSubscriptions(now: UInt64, force: Bool = false) -> [String] {
        let interval = UInt64(max(0, settings.ios.subscription_hours)) * 3600
        return subscriptions.filter { sub in
            if force { return true }
            guard interval > 0 else { return false }
            guard let updated = sub.updated_at else { return true }
            return now >= updated && now - updated >= interval
        }.map(\.id)
    }
}
extension VPNServer {
    public var outboundTag: String { "server-" + fingerprint }
}
