import Foundation

public enum TunnelConfiguration {
    public static func make(profile: VPNProfile, apiPort: Int = 0, secret: String = "") throws -> String {
        try profile.validate()
        guard let server = profile.selectedServer else { throw FoxError.noServer }
        var outbound: [String: Any] = ["type": "vless", "tag": "vpn", "server": server.address, "server_port": server.port, "uuid": server.uuid, "domain_resolver": "bootstrap"]
        let p = server.params
        if let flow = p["flow"], !flow.isEmpty { outbound["flow"] = flow }
        if server.security != "none" {
            var tls: [String: Any] = ["enabled": true, "server_name": p["sni"] ?? server.address]
            if let fp = p["fp"] { tls["utls"] = ["enabled": true, "fingerprint": fp] }
            if let alpn = p["alpn"] { tls["alpn"] = alpn.components(separatedBy: ",") }
            if server.security == "reality" { tls["reality"] = ["enabled": true, "public_key": p["pbk"] ?? "", "short_id": p["sid"] ?? ""] }
            outbound["tls"] = tls
        }
        if server.transport == "ws" {
            var transport: [String: Any] = ["type": "ws", "path": p["path"] ?? "/"]
            if let host = p["host"] { transport["headers"] = ["Host": host] }
            outbound["transport"] = transport
        } else if server.transport == "grpc" { outbound["transport"] = ["type": "grpc", "service_name": p["serviceName"] ?? ""] }
        var routes: [[String: Any]] = [["action": "sniff"], ["protocol": "dns", "action": "hijack-dns"]], dnsRules: [[String: Any]] = []
        if [.smart, .custom].contains(profile.settings.mode) {
            for input in profile.rules {
                let rule = try input.normalized()
                let matcher: [String: Any] = rule.domain.hasPrefix("*.") ? ["domain_regex": ["^.+\\." + NSRegularExpression.escapedPattern(for: String(rule.domain.dropFirst(2))) + "$"]] : ["domain": [rule.domain]]
                routes.append(matcher.merging(["action": "route", "outbound": rule.route]) { _, rhs in rhs })
                dnsRules.append(matcher.merging(["action": "route", "server": rule.route == "direct" ? "dns-direct" : "dns-vpn"]) { _, rhs in rhs })
            }
            if profile.settings.mode == .smart {
                routes.append(["domain_suffix": ["ru", "su", "xn--p1ai"], "action": "route", "outbound": "direct"])
                dnsRules.append(["domain_suffix": ["ru", "su", "xn--p1ai"], "action": "route", "server": "dns-direct"])
            }
        }
        let provider: (String, String) = switch profile.settings.dns_provider { case "google": ("8.8.8.8", "dns.google"); case "quad9": ("9.9.9.9", "dns.quad9.net"); default: ("1.1.1.1", "cloudflare-dns.com") }
        func dns(_ tag: String, _ detour: String) -> [String: Any] {
            if profile.settings.dns_transport == "local" { return ["type": "local", "tag": tag] }
            var result: [String: Any] = ["type": profile.settings.dns_transport, "tag": tag, "server": provider.0, "tls": ["server_name": provider.1]]
            if detour != "direct" { result["detour"] = detour }
            return result
        }
        let final = profile.settings.mode == .direct ? "direct" : "vpn"
        var config: [String: Any] = ["log": ["disabled": true], "inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.29.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": true, "strict_route": true, "stack": "gvisor", "mtu": 1400]], "outbounds": [outbound, ["type": "direct", "tag": "direct"]], "route": ["auto_detect_interface": true, "rules": routes, "final": final], "dns": ["reverse_mapping": true, "servers": [["type": "local", "tag": "bootstrap"], dns("dns-direct", "direct"), dns("dns-vpn", "vpn")], "rules": dnsRules, "final": final == "direct" ? "dns-direct" : "dns-vpn"]]
        if apiPort > 0 { config["experimental"] = ["clash_api": ["external_controller": "127.0.0.1:\(apiPort)", "secret": secret]] }
        return String(decoding: try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]), as: UTF8.self)
    }
}
