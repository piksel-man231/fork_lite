import Foundation

public enum RunMode: Equatable, Sendable {
    /// Боевой режим: TUN перехватывает весь трафик Mac (нужен root).
    case tun
    /// Проверочный режим без root: локальный mixed-прокси, правила те же.
    case proxy(port: Int)
}

/// Builds a sing-box config from the Xray toggle and ordered rules.
public struct ConfigBuilder {
    public var settings: Settings
    public var xray: XrayProfile?
    public var mode: RunMode = .tun
    public var logPath: String?
    public var clashPort: Int?
    public var clashSecret: String?

    public init(settings: Settings, xray: XrayProfile?, mode: RunMode = .tun, logPath: String? = nil,
                clashPort: Int? = nil, clashSecret: String? = nil) {
        self.settings = settings; self.xray = xray; self.mode = mode
        self.logPath = logPath; self.clashPort = clashPort; self.clashSecret = clashSecret
    }

    public var xrayActive: Bool { settings.xrayOn && xray != nil }
    public var needsCore: Bool { xrayActive }

    func effectiveRules() -> [Rule] {
        settings.rules.filter { $0.enabled && !$0.value.isEmpty &&
            ($0.target != .xray || xrayActive) }
    }

    /// Порт локального SOCKS сопроцесса xray (xhttp).
    public static let sidecarPort = 19081

    static func tlsObject(_ x: XrayProfile) -> [String: Any]? {
        switch x.security {
        case "reality":
            return ["enabled": true, "server_name": x.serverName,
                    "utls": ["enabled": true, "fingerprint": x.fingerprint],
                    "reality": ["enabled": true, "public_key": x.publicKey, "short_id": x.shortId] as [String: Any]]
        case "tls":
            var t: [String: Any] = ["enabled": true, "server_name": x.serverName,
                                    "utls": ["enabled": true, "fingerprint": x.fingerprint]]
            let alpn = x.alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            if !alpn.isEmpty { t["alpn"] = alpn }
            return t
        default: return nil
        }
    }

    /// Выход «xray»: vless (tcp/ws) напрямую в sing-box либо SOCKS к сопроцессу xray (xhttp, его sing-box не умеет).
    static func outbound(for x: XrayProfile) -> [String: Any] {
        if x.needsSidecar {
            return ["type": "socks", "tag": "xray", "server": "127.0.0.1", "server_port": sidecarPort, "version": "5"]
        }
        var o: [String: Any] = ["type": "vless", "tag": "xray", "server": x.server, "server_port": x.port,
                                "uuid": x.uuid, "domain_resolver": "dns-local"]
        if let tls = tlsObject(x) { o["tls"] = tls }
        if x.network == "ws" {
            var t: [String: Any] = ["type": "ws", "path": x.path.isEmpty ? "/" : x.path]
            if !x.host.isEmpty { t["headers"] = ["Host": x.host] }
            o["transport"] = t
        }
        if x.network == "tcp", !x.flow.isEmpty { o["flow"] = x.flow }
        return o
    }

    static func matchField(_ k: RuleKind) -> String {
        switch k {
        case .domain: return "domain"
        case .domainSuffix: return "domain_suffix"
        case .domainKeyword: return "domain_keyword"
        case .ipCidr: return "ip_cidr"
        case .processName: return "process_name"
        case .port: return "port"
        }
    }

    public func build() -> [String: Any] {
        var outbounds: [[String: Any]] = [["type": "direct", "tag": "direct"]]
        if let x = xray, xrayActive { outbounds.append(Self.outbound(for: x)) }
        // DNS: домены каждого выхода резолвятся через его же канал, иначе утечка/неверные внутренние адреса.
        var dnsServers: [[String: Any]] = [["type": "udp", "tag": "dns-local", "server": "223.5.5.5"]]
        if xrayActive { dnsServers.append(["type": "https", "tag": "dns-xray", "server": "1.1.1.1", "detour": "xray"]) }

        var dnsRules: [[String: Any]] = []
        if let x = xray, xrayActive, Self.isDomain(x.server) {
            dnsRules.append(["domain": [x.server], "server": "dns-local"])
        }
        var routeRules: [[String: Any]] = []
        if case .tun = mode {
            routeRules.append(["action": "sniff"])
            routeRules.append(["protocol": "dns", "action": "hijack-dns"])
            // Сопроцесс xray (для xhttp) сам ходит на сервер — его трафик не должен возвращаться в туннель.
            if let x = xray, xrayActive, x.needsSidecar {
                routeRules.append(["process_name": ["xray"], "action": "route", "outbound": "direct"])
            }
        } else {
            routeRules.append(["action": "sniff"])
        }
        for r in effectiveRules() {
            let field = Self.matchField(r.kind)
            let match: Any = r.kind == .port ? Int(r.value) as Any : r.value
            if r.kind == .port, Int(r.value) == nil { continue }
            if r.target == .block {
                routeRules.append([field: [match], "action": "reject"])
                continue
            }
            routeRules.append([field: [match], "action": "route", "outbound": r.target.rawValue])
            if r.kind == .domain || r.kind == .domainSuffix || r.kind == .domainKeyword {
                let server = r.target == .xray ? "dns-xray" : "dns-local"
                let dr: [String: Any] = [field: [r.value], "server": server]
                dnsRules.append(dr)
            }
        }

        var inbounds: [[String: Any]]
        switch mode {
        case .tun:
            let tun: [String: Any] = ["type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"],
                                      "auto_route": true, "strict_route": false, "stack": "system"]
            inbounds = [tun]
        case .proxy(let port):
            inbounds = [["type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port]]
        }

        var log: [String: Any] = ["level": "info", "timestamp": true]
        if let p = logPath { log["output"] = p }

        var experimental: [String: Any]?
        if let port = clashPort, let secret = clashSecret, !secret.isEmpty {
            experimental = ["clash_api": ["external_controller": "127.0.0.1:\(port)", "secret": secret]]
        }
        var config: [String: Any] = [
            "log": log,
            "dns": ["servers": dnsServers, "rules": dnsRules,
                    "final": xrayActive ? "dns-xray" : "dns-local",
                    "strategy": "ipv4_only", "reverse_mapping": true] as [String: Any],
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": ["rules": routeRules, "final": xrayActive ? "xray" : "direct",
                      "auto_detect_interface": true, "find_process": true,
                      "default_domain_resolver": "dns-local"] as [String: Any],
        ]
        if let e = experimental { config["experimental"] = e }
        return config
    }

    public func json() throws -> Data {
        try JSONSerialization.data(withJSONObject: build(), options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }


    static func isDomain(_ s: String) -> Bool {
        s.contains(where: { $0.isLetter }) && !s.contains(":")
    }
}
