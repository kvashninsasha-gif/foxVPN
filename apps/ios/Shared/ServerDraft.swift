import Foundation

public struct ServerDraft {
    public var name: String, group: String, address: String, port: String, uuid: String, transport: String, security: String
    public var sni: String, publicKey: String, shortID: String, flow: String, fingerprint: String, path: String, host: String, service: String, alpn: String
    public var favorite: Bool
    private let original: VPNServer?
    public init(server: VPNServer? = nil) {
        original = server; name = server?.name ?? ""; group = server?.group ?? "Основные"; favorite = server?.favorite ?? false
        address = server?.address ?? ""; port = String(server?.port ?? 443); uuid = server?.uuid ?? ""
        transport = server?.transport ?? "tcp"; security = server?.security ?? "tls"
        let p = server?.params ?? [:]
        sni = p["sni"] ?? ""; publicKey = p["pbk"] ?? ""; shortID = p["sid"] ?? ""; flow = p["flow"] ?? ""; fingerprint = p["fp"] ?? ""
        path = p["path"] ?? ""; host = p["host"] ?? ""; service = p["serviceName"] ?? ""; alpn = p["alpn"] ?? ""
    }
    public func server() throws -> VPNServer {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard let port = Int(port), (1...65535).contains(port), !trimmed.isEmpty else { throw FoxError.invalid("Укажите адрес сервера и порт от 1 до 65535.") }
        var params = original?.params ?? [:]
        for (key, value) in ["sni": sni, "pbk": publicKey, "sid": shortID, "flow": flow, "fp": fingerprint, "path": path, "host": host, "serviceName": service, "alpn": alpn] {
            let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if value.isEmpty { params.removeValue(forKey: key) } else { params[key] = value }
        }
        params["type"] = transport; params["security"] = security
        if security != "reality" { params.removeValue(forKey: "pbk"); params.removeValue(forKey: "sid") }
        if transport != "ws" { params.removeValue(forKey: "path"); params.removeValue(forKey: "host") }
        if transport != "grpc" { params.removeValue(forKey: "serviceName") }
        var components = URLComponents(); components.scheme = "vless"; components.user = uuid.trimmingCharacters(in: .whitespacesAndNewlines)
        components.host = trimmed.contains(":") ? "[\(trimmed)]" : trimmed; components.port = port
        components.fragment = name.trimmingCharacters(in: .whitespacesAndNewlines)
        components.queryItems = params.keys.sorted().map { URLQueryItem(name: $0, value: params[$0]) }
        guard let uri = components.string else { throw FoxError.invalid("Некорректный адрес сервера.") }
        var value = try VPNServer.parse(uri); value.group = group.trimmingCharacters(in: .whitespacesAndNewlines); value.favorite = favorite
        if let original {
            value.id = original.id; value.subscription = original.subscription
            if value.fingerprint == original.fingerprint {
                value.latency_ms = original.latency_ms; value.download_mbps = original.download_mbps; value.status = original.status
                value.successes = original.successes; value.failures = original.failures; value.last_error = original.last_error
            }
        }
        try value.validate(); return value
    }
}
