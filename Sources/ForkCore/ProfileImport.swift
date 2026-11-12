import Foundation

/// Import proxy links and Clash YAML profiles.
public enum ProfileImport {
    static let schemes = ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://"]

    /// Один профиль (первый подошедший). Ошибка — по-русски и понятная.
    public static func parse(_ text: String) throws -> XrayProfile {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.contains("[Interface]") && t.contains("[Peer]") { return try parseWireGuard(t) }
        if schemes.contains(where: t.hasPrefix) { return try parseLink(t.split(whereSeparator: \.isNewline).first.map(String.init) ?? t) }
        return try parseClashYAML(t)
    }

    /// Все подходящие профили: несколько ссылок по строкам или все vless-прокси из yaml. Негодные пропускает.
    public static func parseMany(_ text: String) throws -> [XrayProfile] {
        let raw = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if raw.contains("[Interface]") && raw.contains("[Peer]") { return [try parseWireGuard(raw)] }
        // Some subscriptions return Base64 encoded lists of proxy links.
        let compact = raw.filter { !$0.isWhitespace }
        let decoded = Data(base64Encoded: compact).flatMap { String(data: $0, encoding: .utf8) }
        let t = decoded.map { value in schemes.contains(where: value.contains) ? value : raw } ?? raw
        var out: [XrayProfile]
        if t.contains("proxies:") {
            out = proxyBlocks(t).compactMap { try? profile(fromClash: $0) }
        } else {
            out = t.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { line in schemes.contains(where: line.hasPrefix) }.compactMap { try? parseLink($0) }
        }
        if out.isEmpty { _ = try parse(t) }   // пробуем как одиночный: даст внятную ошибку
        if out.isEmpty { throw ForkError.importFailed("Не нашёл поддерживаемых профилей") }
        // Уберём повторы внутри самой вставки.
        var uniq: [XrayProfile] = []
        for p in out where !uniq.contains(p) { uniq.append(p) }
        return uniq
    }

    // vless://uuid@host:port?type=ws|xhttp|tcp&security=reality|tls|none&sni=..&fp=..&pbk=..&sid=..&flow=..
    //                       &path=..&host=..&mode=..&alpn=..&extra={json}#name
    public static func parseLink(_ link: String) throws -> XrayProfile {
        if link.hasPrefix("vmess://") { return try parseVMess(link) }
        if link.hasPrefix("ss://") { return try parseShadowsocks(link) }
        if link.hasPrefix("trojan://") || link.hasPrefix("hysteria2://") || link.hasPrefix("hy2://") || link.hasPrefix("tuic://") {
            return try parseCredentialLink(link)
        }
        guard let u = URLComponents(string: link), let uuid = u.user, let host = u.host, let port = u.port else {
            throw ForkError.importFailed("Не разобрал ссылку vless://")
        }
        let q = Dictionary((u.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
        if let enc = q["encryption"], !enc.isEmpty, enc != "none" {
            throw ForkError.importFailed("VLESS encryption «\(enc)» не поддерживается")
        }
        return try make(name: u.fragment?.removingPercentEncoding ?? host, server: host, port: port, uuid: uuid,
                        type: q["type"] ?? "tcp", security: q["security"] ?? "none", sni: q["sni"] ?? "",
                        fp: q["fp"] ?? "", pbk: q["pbk"] ?? "", sid: q["sid"] ?? "", flow: q["flow"] ?? "",
                        path: q["path"] ?? "", host: q["host"] ?? "", mode: q["mode"] ?? "", alpn: q["alpn"] ?? "",
                        extra: q["extra"] ?? "", allowInsecure: ["1", "true"].contains(q["allowInsecure"] ?? q["insecure"] ?? ""))
    }

    static func decodedBase64(_ text: String) -> String? {
        var value = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        return Data(base64Encoded: value).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func parseVMess(_ link: String) throws -> XrayProfile {
        guard let decoded = decodedBase64(String(link.dropFirst("vmess://".count))),
              let data = decoded.data(using: .utf8), let flat = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let host = flat["add"] as? String, let port = Int(String(describing: flat["port"] ?? "")),
              let uuid = flat["id"] as? String, (1...65535).contains(port) else {
            throw ForkError.importFailed("Не разобрал ссылку vmess://")
        }
        var profile = XrayProfile(name: flat["ps"] as? String ?? host, server: host, port: port, uuid: uuid,
                                  serverName: flat["sni"] as? String ?? host,
                                  network: flat["net"] as? String ?? "tcp",
                                  security: (flat["tls"] as? String) == "tls" ? "tls" : "none",
                                  path: flat["path"] as? String ?? "", host: flat["host"] as? String ?? "")
        profile.protocolType = "vmess"
        profile.method = flat["scy"] as? String ?? "auto"
        profile.alterId = Int(String(describing: flat["aid"] ?? "0")) ?? 0
        return profile
    }

    static func parseShadowsocks(_ link: String) throws -> XrayProfile {
        var body = String(link.dropFirst(5))
        let fragment = body.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        body = String(fragment[0]); let name = fragment.count > 1 ? String(fragment[1]).removingPercentEncoding : nil
        if let at = body.firstIndex(of: "@") {
            let user = String(body[..<at])
            if !user.contains(":"), let decoded = decodedBase64(user) { body = decoded + String(body[at...]) }
        } else if let decoded = decodedBase64(body) { body = decoded }
        guard let u = URLComponents(string: "ss://" + body), let host = u.host, let port = u.port,
              let method = u.user, let password = u.password, !method.isEmpty, !password.isEmpty,
              (1...65535).contains(port) else { throw ForkError.importFailed("Не разобрал ссылку ss://") }
        var profile = XrayProfile(name: name ?? host, server: host, port: port, uuid: "", serverName: host, security: "none")
        profile.protocolType = "shadowsocks"; profile.method = method; profile.password = password
        return profile
    }

    static func parseCredentialLink(_ link: String) throws -> XrayProfile {
        guard let u = URLComponents(string: link), let host = u.host, let port = u.port,
              let credential = u.user, !credential.isEmpty, (1...65535).contains(port) else {
            throw ForkError.importFailed("Не разобрал ссылку прокси")
        }
        let q = Dictionary((u.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
        let kind = u.scheme == "hy2" ? "hysteria2" : u.scheme ?? ""
        var profile = XrayProfile(name: u.fragment?.removingPercentEncoding ?? host, server: host, port: port,
                                  uuid: kind == "tuic" ? credential : "", serverName: q["sni"] ?? host,
                                  network: q["type"] ?? "tcp", security: "tls", path: q["path"] ?? "", host: q["host"] ?? "")
        profile.protocolType = kind
        profile.password = kind == "tuic" ? (u.password ?? "") : credential
        profile.obfs = q["obfs"] ?? ""; profile.obfsPassword = q["obfs-password"] ?? ""
        profile.upMbps = Int(q["upmbps"] ?? "") ?? 0; profile.downMbps = Int(q["downmbps"] ?? "") ?? 0
        profile.alpn = q["alpn"] ?? ""
        profile.allowInsecure = ["1", "true"].contains(q["insecure"] ?? "")
        return profile
    }

    static func parseWireGuard(_ text: String) throws -> XrayProfile {
        var section = ""
        var fields: [String: String] = [:]
        var peerCount = 0
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.split(separator: "#", maxSplits: 1).first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast()).lowercased()
                if section == "peer" { peerCount += 1 }
                continue
            }
            guard let equal = line.firstIndex(of: "="), ["interface", "peer"].contains(section) else { continue }
            let key = line[..<equal].trimmingCharacters(in: .whitespaces).lowercased()
            fields["\(section).\(key)"] = line[line.index(after: equal)...].trimmingCharacters(in: .whitespaces)
        }
        let basic = ["privatekey", "address", "dns", "mtu", "table", "listenport"]
        let awg = fields.filter { $0.key.hasPrefix("interface.") && !basic.contains(String($0.key.dropFirst("interface.".count))) }
        if let unsupported = awg.keys.first(where: { !AwgConfigBuilder.keys.contains(String($0.dropFirst("interface.".count))) }) {
            throw ForkError.importFailed("Не поддерживается директива \(unsupported)")
        }
        guard peerCount == 1, let endpoint = fields["peer.endpoint"], let url = URLComponents(string: "udp://" + endpoint),
              let host = url.host, let port = url.port, (1...65535).contains(port),
              let privateKey = fields["interface.privatekey"], !privateKey.isEmpty,
              let publicKey = fields["peer.publickey"], !publicKey.isEmpty,
              let addresses = fields["interface.address"], !addresses.isEmpty else {
            throw ForkError.importFailed("В WireGuard-конфигурации нужны Address, PrivateKey, PublicKey и Endpoint")
        }
        var profile = XrayProfile(name: host, server: host, port: port, uuid: "", serverName: host, security: "none")
        profile.protocolType = awg.isEmpty && fields["peer.advancedsecurity"] == nil ? "wireguard" : "amneziawg"
        profile.privateKey = privateKey; profile.publicKeyPeer = publicKey
        profile.preSharedKey = fields["peer.presharedkey"] ?? ""
        profile.addresses = addresses.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        profile.allowedIPs = (fields["peer.allowedips"] ?? "0.0.0.0/0, ::/0").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        profile.mtu = Int(fields["interface.mtu"] ?? "") ?? 0
        profile.keepalive = Int(fields["peer.persistentkeepalive"] ?? "") ?? 0
        profile.awgParameters = Dictionary(uniqueKeysWithValues: awg.map { (String($0.key.dropFirst("interface.".count)), $0.value) })
        if let advanced = fields["peer.advancedsecurity"] {
            profile.awgPeerParameters["AdvancedSecurity"] = advanced
        }
        profile.dnsServer = fields["interface.dns"]?.split(separator: ",").first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        if profile.protocolType == "amneziawg" { _ = try AwgConfigBuilder.config(profile) }
        return profile
    }

    /// Единая сборка и проверка профиля (ссылка и Clash-yaml приходят сюда).
    static func make(name: String, server: String, port: Int, uuid: String, type: String, security: String,
                     sni: String, fp: String, pbk: String, sid: String, flow: String,
                     path: String, host: String, mode: String, alpn: String, extra: String,
                     allowInsecure: Bool = false) throws -> XrayProfile {
        let network = type == "splithttp" ? "xhttp" : type
        guard XrayProfile.networks.contains(network) else {
            throw ForkError.importFailed("Транспорт «\(type)» пока не поддерживается: только tcp, ws, xhttp")
        }
        guard XrayProfile.securities.contains(security) else {
            throw ForkError.importFailed("Безопасность «\(security)» не поддерживается: только reality, tls, none")
        }
        if security == "reality" && network == "ws" {
            throw ForkError.importFailed("Reality не работает поверх ws (только tcp или xhttp)")
        }
        if security == "reality" && pbk.isEmpty { throw ForkError.importFailed("Для Reality нужен публичный ключ (pbk)") }
        // flow (vision) работает только поверх tcp; для ws/xhttp игнорируем, а не ломаем запуск.
        var profile = XrayProfile(name: name, server: server, port: port, uuid: uuid, flow: network == "tcp" ? flow : "",
                           serverName: sni.isEmpty ? (host.isEmpty ? server : host) : sni,
                           publicKey: pbk, shortId: sid, fingerprint: fp.isEmpty ? "chrome" : fp,
                           network: network, security: security,
                           path: path.isEmpty && network != "tcp" ? "/" : path, host: host, mode: mode,
                           alpn: alpn, xhttpExtra: extra)
        profile.allowInsecure = allowInsecure
        return profile
    }

    public static func parseClashYAML(_ yaml: String) throws -> XrayProfile {
        let blocks = proxyBlocks(yaml)
        guard let first = blocks.first(where: { ["vless", "vmess", "trojan", "ss", "hysteria2", "tuic"].contains($0["type"] ?? "") }) else {
            throw ForkError.importFailed("В профиле нет поддерживаемого прокси")
        }
        return try profile(fromClash: first)
    }

    static func profile(fromClash flat: [String: String]) throws -> XrayProfile {
        let kind = flat["type"] ?? ""
        if kind != "vless" {
            guard ["vmess", "trojan", "ss", "hysteria2", "tuic"].contains(kind),
                  let server = flat["server"], let port = Int(flat["port"] ?? ""), (1...65535).contains(port) else {
                throw ForkError.importFailed("Неподдерживаемый тип или неполный профиль")
            }
            var profile = XrayProfile(name: flat["name"] ?? server, server: server, port: port,
                                      uuid: flat["uuid"] ?? "", serverName: flat["servername"] ?? flat["sni"] ?? server,
                                      network: flat["network"] ?? "tcp", security: flat["tls"] == "true" ? "tls" : "none",
                                      path: flat["ws-opts.path"] ?? "", host: flat["ws-opts.headers.Host"] ?? "")
            profile.protocolType = kind == "ss" ? "shadowsocks" : kind
            profile.password = flat["password"] ?? ""; profile.method = flat["cipher"] ?? ""
            profile.alterId = Int(flat["alterId"] ?? "") ?? 0
            profile.obfs = flat["obfs"] ?? ""; profile.obfsPassword = flat["obfs-password"] ?? ""
            profile.upMbps = Int(flat["up"] ?? "") ?? 0; profile.downMbps = Int(flat["down"] ?? "") ?? 0
            profile.allowInsecure = flat["skip-cert-verify"] == "true"
            if kind == "trojan" || kind == "hysteria2" || kind == "tuic" { profile.security = "tls" }
            return profile
        }
        guard let server = flat["server"], let port = Int(flat["port"] ?? ""), let uuid = flat["uuid"] else {
            throw ForkError.importFailed("В профиле не хватает server/port/uuid")
        }
        let network = flat["network"] ?? "tcp"
        let pbk = flat["reality-opts.public-key"] ?? ""
        let security = !pbk.isEmpty ? "reality" : (flat["tls"] == "true" ? "tls" : "none")
        // Mihomo: ws-opts{path,headers{Host}}, xhttp-opts{path,host,mode}.
        let opts = network == "ws" ? "ws-opts" : "xhttp-opts"
        return try make(name: flat["name"] ?? server, server: server, port: port, uuid: uuid, type: network, security: security,
                        sni: flat["servername"] ?? flat["sni"] ?? "", fp: flat["client-fingerprint"] ?? "",
                        pbk: pbk, sid: flat["reality-opts.short-id"] ?? "", flow: flat["flow"] ?? "",
                        path: flat["\(opts).path"] ?? "", host: flat["\(opts).headers.Host"] ?? flat["\(opts).host"] ?? "",
                        mode: flat["xhttp-opts.mode"] ?? "", alpn: "", extra: "",
                        allowInsecure: flat["skip-cert-verify"] == "true")
    }

    /// Минимальный разбор списка `proxies:` в плоские словари (вложенные ключи — «секция.подсекция.ключ»).
    /// Элемент списка — «- » на отступе первого элемента; глубже — вложенные списки (alpn и т.п.), их игнорируем.
    static func proxyBlocks(_ yaml: String) -> [[String: String]] {
        var blocks: [[String: String]] = [], cur: [String: String]?
        var inProxies = false, itemIndent: Int?
        var stack: [(indent: Int, key: String)] = []
        func flush() { if let c = cur { blocks.append(c) }; cur = nil; stack = [] }

        for raw in yaml.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(raw)
            if line.hasPrefix("#") { continue }
            if !line.hasPrefix(" ") && !line.hasPrefix("-") {
                if inProxies { flush() }
                inProxies = line.hasPrefix("proxies:"); itemIndent = nil; continue
            }
            guard inProxies else { continue }
            let lead = line.prefix(while: { $0 == " " }).count
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            var body = trimmed, indent = lead
            if trimmed.hasPrefix("- ") {
                if itemIndent == nil { itemIndent = lead }
                guard lead == itemIndent else { continue }   // вложенный список внутри прокси
                flush(); cur = [:]
                body = String(trimmed.dropFirst(2)); indent = lead + 2
            }
            guard cur != nil, let colon = body.firstIndex(of: ":") else { continue }
            let key = String(body[..<colon])
            let val = body[body.index(after: colon)...].trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
            while let top = stack.last, top.indent >= indent { stack.removeLast() }
            if val.isEmpty { stack.append((indent, key)) }
            else { cur?[(stack.map(\.key) + [key]).joined(separator: ".")] = val }
        }
        flush()
        return blocks
    }
}
