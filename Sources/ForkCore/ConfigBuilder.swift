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
    public var awgInterface: String?

    public init(settings: Settings, xray: XrayProfile?, mode: RunMode = .tun, logPath: String? = nil,
                clashPort: Int? = nil, clashSecret: String? = nil, awgInterface: String? = nil) {
        self.settings = settings; self.xray = xray; self.mode = mode
        self.logPath = logPath; self.clashPort = clashPort; self.clashSecret = clashSecret
        self.awgInterface = awgInterface
    }

    public var xrayActive: Bool {
        settings.xrayOn && xray != nil && (xray?.protocolType != "amneziawg" || awgInterface != nil)
    }
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
        if x.protocolType != "vless" {
            var o: [String: Any] = ["type": x.protocolType, "tag": "xray", "server": x.server,
                                    "server_port": x.port, "domain_resolver": "dns-local"]
            switch x.protocolType {
            case "vmess":
                o["uuid"] = x.uuid; o["security"] = x.method.isEmpty ? "auto" : x.method
                o["alter_id"] = x.alterId
            case "trojan": o["password"] = x.password
            case "shadowsocks": o["method"] = x.method; o["password"] = x.password
            case "hysteria2":
                o["password"] = x.password
                if x.upMbps > 0 { o["up_mbps"] = x.upMbps }
                if x.downMbps > 0 { o["down_mbps"] = x.downMbps }
                if !x.obfs.isEmpty { o["obfs"] = ["type": x.obfs, "password": x.obfsPassword] }
            case "tuic": o["uuid"] = x.uuid; o["password"] = x.password
            default: break
            }
            if x.protocolType == "trojan" || x.protocolType == "hysteria2" || x.protocolType == "tuic" {
                if x.protocolType == "hysteria2" || x.protocolType == "tuic" {
                    var tls: [String: Any] = ["enabled": true, "server_name": x.serverName]
                    if !x.alpn.isEmpty { tls["alpn"] = x.alpn.split(separator: ",").map(String.init) }
                    if x.allowInsecure { tls["insecure"] = true }
                    o["tls"] = tls
                } else {
                    var tls = tlsObject(x) ?? ["enabled": true, "server_name": x.serverName]
                    if x.allowInsecure { tls["insecure"] = true }
                    o["tls"] = tls
                }
            } else if x.protocolType == "vmess", let tls = tlsObject(x) {
                var configured = tls
                if x.allowInsecure { configured["insecure"] = true }
                o["tls"] = configured
            }
            if (x.protocolType == "vmess" || x.protocolType == "trojan") && x.network == "ws" {
                var t: [String: Any] = ["type": "ws", "path": x.path.isEmpty ? "/" : x.path]
                if !x.host.isEmpty { t["headers"] = ["Host": x.host] }
                o["transport"] = t
            }
            return o
        }
        var o: [String: Any] = ["type": "vless", "tag": "xray", "server": x.server, "server_port": x.port,
                                "uuid": x.uuid, "domain_resolver": "dns-local"]
        if let tls = tlsObject(x) {
            var configured = tls
            if x.allowInsecure { configured["insecure"] = true }
            o["tls"] = configured
        }
        if x.network == "ws" {
            var t: [String: Any] = ["type": "ws", "path": x.path.isEmpty ? "/" : x.path]
            if !x.host.isEmpty { t["headers"] = ["Host": x.host] }
            o["transport"] = t
        }
        if x.network == "tcp", !x.flow.isEmpty { o["flow"] = x.flow }
        return o
    }

    static func wireGuardEndpoint(for x: XrayProfile) -> [String: Any] {
        var peer: [String: Any] = ["address": x.server, "port": x.port,
                                    "public_key": x.publicKeyPeer,
                                    "allowed_ips": x.allowedIPs.isEmpty ? ["0.0.0.0/0", "::/0"] : x.allowedIPs]
        if !x.preSharedKey.isEmpty { peer["pre_shared_key"] = x.preSharedKey }
        var endpoint: [String: Any] = ["type": "wireguard", "tag": "xray", "address": x.addresses,
                                        "private_key": x.privateKey, "peers": [peer]]
        if x.mtu > 0 { endpoint["mtu"] = x.mtu }
        if isDomain(x.server) { endpoint["domain_resolver"] = "dns-local" }
        return endpoint
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
        if let x = xray, xrayActive {
            if x.protocolType == "amneziawg", let iface = awgInterface {
                outbounds.append(["type": "direct", "tag": "xray", "bind_interface": iface])
            } else if x.protocolType != "wireguard" {
                outbounds.append(Self.outbound(for: x))
            }
        }
        // DNS: домены каждого выхода резолвятся через его же канал, иначе утечка/неверные внутренние адреса.
        var dnsServers: [[String: Any]] = [["type": "udp", "tag": "dns-local", "server": "223.5.5.5"]]
        if xrayActive {
            let dnsAddress = xray?.dnsServer.isEmpty == false ? xray!.dnsServer : "1.1.1.1"
            dnsServers.append(["type": xray?.dnsServer.isEmpty == false ? "udp" : "https",
                               "tag": "dns-xray", "server": dnsAddress, "detour": "xray"])
        }

        var dnsRules: [[String: Any]] = []
        if let x = xray, xrayActive, Self.isDomain(x.server) {
            dnsRules.append(["domain": [x.server], "server": "dns-local"])
        }
        var routeRules: [[String: Any]] = []
        if case .tun = mode {
            routeRules.append(["action": "sniff"])
            routeRules.append(["protocol": "dns", "action": "hijack-dns"])
            if xray?.protocolType == "amneziawg" {
                routeRules.append(["process_name": ["amneziawg-go"], "action": "route", "outbound": "direct"])
            }
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
            var configured = tun
            if let x = xray, xrayActive, x.protocolType == "amneziawg", Self.isIPv4(x.server) {
                configured["route_exclude_address"] = ["\(x.server)/32"]
            }
            inbounds = [configured]
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
        if let x = xray, xrayActive, x.protocolType == "wireguard" {
            config["endpoints"] = [Self.wireGuardEndpoint(for: x)]
        }
        if let e = experimental { config["experimental"] = e }
        return config
    }

    public func json() throws -> Data {
        try JSONSerialization.data(withJSONObject: build(), options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }


    static func isDomain(_ s: String) -> Bool {
        s.contains(where: { $0.isLetter }) && !s.contains(":")
    }

    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
    }
}
