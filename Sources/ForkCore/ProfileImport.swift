import Foundation

/// Импорт VLESS-профилей: ссылки `vless://` (V2Box → «Поделиться») и Clash-yaml (Clash Verge). Можно сразу несколько.
public enum ProfileImport {

    /// Один профиль (первый подошедший). Ошибка — по-русски и понятная.
    public static func parse(_ text: String) throws -> XrayProfile {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("vless://") { return try parseLink(t.split(whereSeparator: \.isNewline).first.map(String.init) ?? t) }
        return try parseClashYAML(t)
    }

    /// Все подходящие профили: несколько ссылок по строкам или все vless-прокси из yaml. Негодные пропускает.
    public static func parseMany(_ text: String) throws -> [XrayProfile] {
        let raw = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // Some subscription endpoints return a Base64 encoded list of vless:// links.
        let compact = raw.filter { !$0.isWhitespace }
        let decoded = Data(base64Encoded: compact).flatMap { String(data: $0, encoding: .utf8) }
        let t = decoded?.contains("vless://") == true ? decoded! : raw
        var out: [XrayProfile]
        if t.contains("proxies:") {
            out = proxyBlocks(t).compactMap { try? profile(fromClash: $0) }
        } else {
            out = t.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.hasPrefix("vless://") }.compactMap { try? parseLink($0) }
        }
        if out.isEmpty { _ = try parse(t) }   // пробуем как одиночный: даст внятную ошибку
        if out.isEmpty { throw ForkError.importFailed("Не нашёл ни одного подходящего профиля VLESS+Reality") }
        // Уберём повторы внутри самой вставки.
        var uniq: [XrayProfile] = []
        for p in out where !uniq.contains(p) { uniq.append(p) }
        return uniq
    }

    // vless://uuid@host:port?type=ws|xhttp|tcp&security=reality|tls|none&sni=..&fp=..&pbk=..&sid=..&flow=..
    //                       &path=..&host=..&mode=..&alpn=..&extra={json}#name
    public static func parseLink(_ link: String) throws -> XrayProfile {
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
                        extra: q["extra"] ?? "")
    }

    /// Единая сборка и проверка профиля (ссылка и Clash-yaml приходят сюда).
    static func make(name: String, server: String, port: Int, uuid: String, type: String, security: String,
                     sni: String, fp: String, pbk: String, sid: String, flow: String,
                     path: String, host: String, mode: String, alpn: String, extra: String) throws -> XrayProfile {
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
        return XrayProfile(name: name, server: server, port: port, uuid: uuid, flow: network == "tcp" ? flow : "",
                           serverName: sni.isEmpty ? (host.isEmpty ? server : host) : sni,
                           publicKey: pbk, shortId: sid, fingerprint: fp.isEmpty ? "chrome" : fp,
                           network: network, security: security,
                           path: path.isEmpty && network != "tcp" ? "/" : path, host: host, mode: mode,
                           alpn: alpn, xhttpExtra: extra)
    }

    public static func parseClashYAML(_ yaml: String) throws -> XrayProfile {
        let blocks = proxyBlocks(yaml)
        guard let vless = blocks.first(where: { $0["type"] == "vless" }) else {
            throw ForkError.importFailed("В профиле нет vless-прокси")
        }
        return try profile(fromClash: vless)
    }

    static func profile(fromClash flat: [String: String]) throws -> XrayProfile {
        guard flat["type"] == "vless" else { throw ForkError.importFailed("В профиле нет vless-прокси") }
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
                        mode: flat["xhttp-opts.mode"] ?? "", alpn: "", extra: "")
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
