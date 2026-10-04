import Foundation

public enum CoreRequest {
    case statistics, route, measure(String)
    public init?(data: Data, allowedTags: Set<String>) {
        guard data.count <= 256 else { return nil }
        if data == Data("stats".utf8) { self = .statistics; return }
        if data == Data("route".utf8) { self = .route; return }
        guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: String],
              value.count == 1, let tag = value["measure"], allowedTags.contains(tag) else { return nil }
        self = .measure(tag)
    }
    public var path: String {
        switch self {
        case .statistics: return "/connections"
        case .route: return "/proxies"
        case .measure(let tag): return "/proxies/\(tag)/delay?timeout=8000&url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
        }
    }
    public var timeout: Double { if case .measure = self { return 9 }; return 2 }
    public func safeResponse(_ data: Data, allowedTags: Set<String>) -> Data? {
        guard data.count <= 2_000_000, let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        switch self {
        case .statistics:
            guard let upload = value["uploadTotal"] as? NSNumber, let download = value["downloadTotal"] as? NSNumber, upload.int64Value >= 0, download.int64Value >= 0 else { return nil }
            return try? JSONSerialization.data(withJSONObject: ["upload": upload.int64Value, "download": download.int64Value])
        case .measure:
            guard let delay = (value["delay"] as? NSNumber)?.intValue, (1...60_000).contains(delay) else { return nil }
            return try? JSONSerialization.data(withJSONObject: ["delay": delay])
        case .route:
            guard let proxies = value["proxies"] as? [String: [String: Any]] else { return nil }
            let now = proxies["vpn"]?["now"] as? String
            var delays: [String: Int] = [:]
            for tag in allowedTags {
                if let history = proxies[tag]?["history"] as? [[String: Any]], let last = history.last,
                   let delay = (last["delay"] as? NSNumber)?.intValue, (1...60_000).contains(delay) { delays[tag] = delay }
            }
            return try? JSONEncoder().encode(TunnelRouteSnapshot(active_tag: now.flatMap { allowedTags.contains($0) ? $0 : nil }, delays: delays))
        }
    }
}
