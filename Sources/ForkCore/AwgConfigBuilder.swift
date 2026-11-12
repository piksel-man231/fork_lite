import Foundation

public enum AwgConfigBuilder {
    static let keys: Set<String> = [
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
        "i1", "i2", "i3", "i4", "i5", "headerprotectionkey", "contentpaddingaddition",
        "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout",
        "maxhandshakeattempts", "randomtrailers", "disablecookies"
    ]

    public static func config(_ p: XrayProfile) throws -> String {
        guard p.protocolType == "amneziawg", !p.privateKey.isEmpty, !p.publicKeyPeer.isEmpty,
              !p.addresses.isEmpty, (1...65535).contains(p.port) else {
            throw ForkError.importFailed("Неполный профиль AmneziaWG")
        }
        func clean(_ value: String) throws -> String {
            guard !value.isEmpty, value.count <= 1024,
                  !value.unicodeScalars.contains(where: { CharacterSet.newlines.contains($0) || $0.value < 32 }) else {
                throw ForkError.importFailed("Недопустимое значение в профиле AmneziaWG")
            }
            return value
        }
        var lines = ["[Interface]", "PrivateKey = \(try clean(p.privateKey))",
                     "Address = \(try clean(p.addresses.joined(separator: ", ")))", "Table = off"]
        if p.mtu > 0 { lines.append("MTU = \(p.mtu)") }
        for (key, value) in p.awgParameters.sorted(by: { $0.key < $1.key }) {
            guard keys.contains(key.lowercased()) else {
                throw ForkError.importFailed("Неподдерживаемый параметр AmneziaWG: \(key)")
            }
            lines.append("\(key) = \(try clean(value))")
        }
        let host = p.server.contains(":") ? "[\(p.server)]" : p.server
        lines += ["", "[Peer]", "PublicKey = \(try clean(p.publicKeyPeer))",
                  "Endpoint = \(try clean(host)):\(p.port)",
                  "AllowedIPs = \(try clean(p.allowedIPs.joined(separator: ", ")))"]
        if !p.preSharedKey.isEmpty { lines.append("PresharedKey = \(try clean(p.preSharedKey))") }
        if p.keepalive > 0 { lines.append("PersistentKeepalive = \(p.keepalive)") }
        if let advanced = p.awgPeerParameters["AdvancedSecurity"] {
            lines.append("AdvancedSecurity = \(try clean(advanced))")
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
