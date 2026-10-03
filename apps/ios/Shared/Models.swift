import Foundation
import CryptoKit

public enum FoxError: LocalizedError {
    case invalid(String), storage, locked, noServer
    public var errorDescription: String? {
        switch self {
        case .invalid(let message): return message
        case .storage: return "Не удалось сохранить защищённый профиль."
        case .locked: return "Разблокируйте iPhone для доступа к профилю."
        case .noServer: return "Добавьте и выберите VPN-сервер."
        }
    }
}

public enum RoutingMode: String, Codable, CaseIterable, Identifiable {
    case smart, vpn, direct, custom
    public var id: String { rawValue }
    public var title: String { switch self { case .smart: return "Умный"; case .vpn: return "VPN"; case .direct: return "Напрямую"; case .custom: return "Мои правила" } }
    public var detail: String { switch self { case .smart: return "Российские домены напрямую, остальные через VPN."; case .vpn: return "Весь трафик через выбранный сервер."; case .direct: return "Трафик напрямую через обычное соединение."; case .custom: return "Ваши исключения, остальной трафик через VPN." } }
}

public struct VPNServer: Codable, Identifiable, Equatable {
    public var id: String
    public var name: String
    public var address: String
    public var port: Int
    public var uuid: String
    public var transport: String
    public var security: String
    public var params: [String: String]
    public var favorite: Bool
    public var group: String
    public var subscription: String?
    public var latency_ms: UInt64?
    public var download_mbps: Double?
    public var status: String
    public var successes: UInt64
    public var failures: UInt64
    public var last_error: String?

    public static func parse(_ raw: String) throws -> VPNServer {
        guard raw.utf8.count <= 16_384, let c = URLComponents(string: raw.trimmingCharacters(in: .whitespacesAndNewlines)), c.scheme == "vless", c.password == nil,
              let user = c.user, let uuid = UUID(uuidString: user), let host = c.host, !host.isEmpty, let port = c.port, (1...65535).contains(port) else {
            throw FoxError.invalid("Нужна корректная VLESS-ссылка с UUID, адресом и портом.")
        }
        var params: [String: String] = [:]
        for item in c.queryItems ?? [] {
            guard params[item.name] == nil else { throw FoxError.invalid("Параметр ссылки повторяется.") }
            params[item.name] = item.value ?? ""
        }
        let name = c.fragment ?? host
        let value = VPNServer(id: UUID().uuidString.lowercased(), name: name, address: host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), port: port, uuid: uuid.uuidString.lowercased(), transport: params["type"] ?? "tcp", security: params["security"] ?? "none", params: params, favorite: false, group: "Основные", subscription: nil, latency_ms: nil, download_mbps: nil, status: "untested", successes: 0, failures: 0, last_error: nil)
        try value.validate()
        return value
    }
    public func validate() throws {
        guard UUID(uuidString: uuid) != nil, (1...65535).contains(port), !address.isEmpty, !address.contains(where: { $0.isWhitespace || $0.isNewline }), name.count <= 200, !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }), ["tcp", "ws", "grpc"].contains(transport), ["none", "tls", "reality"].contains(security) else { throw FoxError.invalid("Некорректные параметры сервера.") }
        guard params["encryption"] == nil || params["encryption"] == "none", !["1", "true"].contains(params["allowInsecure"] ?? "") else { throw FoxError.invalid("Отключение проверки TLS не поддерживается.") }
        let flow = params["flow"] ?? ""
        guard ["", "xtls-rprx-vision"].contains(flow), flow.isEmpty || (transport == "tcp" && security != "none") else { throw FoxError.invalid("Параметр flow несовместим с транспортом.") }
        if let fp = params["fp"], !["chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized", "360", "qq"].contains(fp) { throw FoxError.invalid("Неизвестный TLS fingerprint.") }
        if security == "reality" {
            let key = (params["pbk"] ?? "").replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            let padded = key + String(repeating: "=", count: (4 - key.count % 4) % 4)
            let sid = params["sid"] ?? ""
            guard !(params["sni"] ?? "").isEmpty, Data(base64Encoded: padded)?.count == 32, sid.count <= 16, sid.count % 2 == 0, sid.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { throw FoxError.invalid("Reality требует SNI, publicKey (32 байта) и корректный shortId.") }
        }
    }
    public var fingerprint: String {
        var p = params; ["type", "security", "encryption"].forEach { p.removeValue(forKey: $0) }
        let canonical = [address.lowercased(), String(port), uuid.lowercased(), transport, security] + p.keys.sorted().map { "\($0)=\(p[$0]!)" }
        return SHA256.hash(data: Data(canonical.joined(separator: "\u{0}").utf8)).map { String(format: "%02x", $0) }.joined()
    }
    public func uri() -> String {
        var c = URLComponents(); c.scheme = "vless"; c.user = uuid; c.host = address.contains(":") ? "[\(address)]" : address; c.port = port
        var p = params; p["type"] = transport; p["security"] = security
        c.queryItems = p.keys.sorted().map { URLQueryItem(name: $0, value: p[$0]) }; c.fragment = name
        return c.string ?? ""
    }
}

public struct DomainRule: Codable, Equatable, Identifiable {
    public var domain: String
    public var route: String
    public var id: String { domain }
    public init(domain: String, route: String) { self.domain = domain; self.route = route }
    public static func normalize(_ raw: String) throws -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while value.hasSuffix(".") { value.removeLast() }
        guard !value.isEmpty, !value.contains(where: { "/:@?#*".contains($0) }), let host = URL(string: "https://\(value)")?.host, host.count <= 253 else { throw FoxError.invalid("Введите домен без протокола и пути.") }
        guard host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-") && $0.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) }), !host.split(separator: ".").allSatisfy({ Int($0) != nil }) else { throw FoxError.invalid("Некорректный домен.") }
        return host.lowercased()
    }
    public func normalized() throws -> DomainRule {
        guard ["vpn", "direct"].contains(route) else { throw FoxError.invalid("Неизвестный маршрут.") }
        let wildcard = domain.hasPrefix("*.")
        return DomainRule(domain: (wildcard ? "*." : "") + (try Self.normalize(wildcard ? String(domain.dropFirst(2)) : domain)), route: route)
    }
    public func matches(_ host: String) -> Bool { domain.hasPrefix("*.") ? host.hasSuffix("." + domain.dropFirst(2)) : host == domain }
}

public struct VPNSettings: Codable {
    public var mode: RoutingMode = .smart
    public var dns_provider = "cloudflare"
    public var dns_transport = "https"
    public var auto_connect = false
    public var include_all_networks = true
    public init() {}
    enum CodingKeys: String, CodingKey { case mode, dns_provider, dns_transport, auto_connect, include_all_networks }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decodeIfPresent(RoutingMode.self, forKey: .mode) ?? .smart
        dns_provider = try c.decodeIfPresent(String.self, forKey: .dns_provider) ?? "cloudflare"
        dns_transport = try c.decodeIfPresent(String.self, forKey: .dns_transport) ?? "https"
        auto_connect = try c.decodeIfPresent(Bool.self, forKey: .auto_connect) ?? false
        include_all_networks = try c.decodeIfPresent(Bool.self, forKey: .include_all_networks) ?? true
    }
}
public struct VPNSubscription: Codable, Identifiable {
    public var id: String; public var name: String; public var url: String; public var updated_at: UInt64?
    public init(id: String = UUID().uuidString, name: String, url: String, updated_at: UInt64? = nil) { self.id = id; self.name = name; self.url = url; self.updated_at = updated_at }
}
public struct VPNProfile: Codable {
    public var version = 1
    public var servers: [VPNServer] = []
    public var selected: String?
    public var rules: [DomainRule] = []
    public var subscriptions: [VPNSubscription] = []
    public var settings = VPNSettings()
    public init() {}
    public var selectedServer: VPNServer? { servers.first { $0.id == selected } }
    public func validate() throws {
        guard version == 1, servers.count <= 5000, rules.count <= 5000, ["cloudflare", "google", "quad9"].contains(settings.dns_provider), ["https", "tls", "local"].contains(settings.dns_transport) else { throw FoxError.invalid("Неподдерживаемая версия или настройки профиля.") }
        var ids = Set<String>(), fingerprints = Set<String>(), domains = Set<String>()
        for server in servers {
            try server.validate()
            guard ids.insert(server.id).inserted, fingerprints.insert(server.fingerprint).inserted else { throw FoxError.invalid("В профиле повторяются серверы.") }
        }
        guard selected == nil || ids.contains(selected!) else { throw FoxError.noServer }
        for rule in rules { let normalized = try rule.normalized(); guard domains.insert(normalized.domain).inserted else { throw FoxError.invalid("Доменное правило повторяется.") } }
        var subscriptionIDs = Set<String>()
        for sub in subscriptions { guard subscriptionIDs.insert(sub.id).inserted, !sub.name.isEmpty, sub.name.count <= 200, subscriptions.count <= 5000, let u = URL(string: sub.url), u.scheme == "https", u.host != nil, u.user == nil, u.password == nil else { throw FoxError.invalid("Подписка должна иметь HTTPS-адрес.") } }
    }
    public mutating func importLinks(_ text: String, subscription: String? = nil) throws -> Int {
        guard text.utf8.count <= 4_000_000 else { throw FoxError.invalid("Файл слишком большой.") }
        var added = 0, copy = self
        for line in text.components(separatedBy: .newlines) where !line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            var server = try VPNServer.parse(line); server.subscription = subscription
            if !copy.servers.contains(where: { $0.fingerprint == server.fingerprint }) { copy.servers.append(server); added += 1 }
        }
        if copy.selected == nil { copy.selected = copy.servers.first?.id }
        try copy.validate(); self = copy
        return added
    }
    public func route(for domain: String) throws -> String {
        let host = try DomainRule.normalize(domain)
        if settings.mode == .vpn { return "vpn" }
        if settings.mode == .direct { return "direct" }
        for rule in rules { if try rule.normalized().matches(host) { return rule.route } }
        if settings.mode == .smart, ["ru", "su", "xn--p1ai"].contains(where: { host.hasSuffix("." + $0) }) { return "direct" }
        return "vpn"
    }
}

public enum SubscriptionContent {
    public static func decode(_ data: Data) throws -> String {
        guard data.count <= 4_000_000, let text = String(data: data, encoding: .utf8) else { throw FoxError.invalid("Неподдерживаемый текст подписки.") }
        if text.contains("vless://") { return text }
        let compact = text.filter { !$0.isWhitespace }.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padded = compact + String(repeating: "=", count: (4 - compact.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded), let links = String(data: decoded, encoding: .utf8), links.contains("vless://") else { throw FoxError.invalid("В подписке нет VLESS-ссылок.") }
        return links
    }
}
