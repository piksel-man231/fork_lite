import Foundation

/// Клиентский конфиг xray-core для профилей, которые sing-box не умеет (xhttp):
/// локальный SOCKS5 на 127.0.0.1, наружу — VLESS с нужным транспортом.
public enum XrayConfigBuilder {
    public static func build(_ x: XrayProfile, socksPort: Int = ConfigBuilder.sidecarPort) -> [String: Any] {
        var stream: [String: Any] = ["network": x.network, "security": x.security]
        let alpn = x.alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }

        switch x.security {
        case "reality":
            stream["realitySettings"] = ["serverName": x.serverName, "fingerprint": x.fingerprint,
                                         "publicKey": x.publicKey, "shortId": x.shortId, "spiderX": ""]
        case "tls":
            var t: [String: Any] = ["serverName": x.serverName, "fingerprint": x.fingerprint]
            if !alpn.isEmpty { t["alpn"] = alpn }
            if x.allowInsecure { t["allowInsecure"] = true }
            stream["tlsSettings"] = t
        default: break
        }

        switch x.network {
        case "xhttp":
            var h: [String: Any] = ["path": x.path.isEmpty ? "/" : x.path, "mode": x.mode.isEmpty ? "auto" : x.mode]
            if !x.host.isEmpty { h["host"] = x.host }
            if let d = x.xhttpExtra.data(using: .utf8), let extra = try? JSONSerialization.jsonObject(with: d) { h["extra"] = extra }
            stream["xhttpSettings"] = h
        case "ws":
            var w: [String: Any] = ["path": x.path.isEmpty ? "/" : x.path]
            if !x.host.isEmpty { w["headers"] = ["Host": x.host] }
            stream["wsSettings"] = w
        default: break
        }

        var user: [String: Any] = ["id": x.uuid, "encryption": "none"]
        if x.network == "tcp", !x.flow.isEmpty { user["flow"] = x.flow }

        return [
            "log": ["loglevel": "warning"],
            "inbounds": [["tag": "socks-in", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
                          "settings": ["auth": "noauth", "udp": true]] as [String: Any]],
            "outbounds": [["tag": "proxy", "protocol": "vless",
                           "settings": ["vnext": [["address": x.server, "port": x.port, "users": [user]] as [String: Any]]],
                           "streamSettings": stream] as [String: Any]],
        ]
    }

    public static func json(_ x: XrayProfile, socksPort: Int = ConfigBuilder.sidecarPort) throws -> Data {
        try JSONSerialization.data(withJSONObject: build(x, socksPort: socksPort), options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }
}
