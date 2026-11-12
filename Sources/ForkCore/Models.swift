import Foundation

public enum Target: String, Codable, CaseIterable, Sendable {
    case xray, direct, block
}

public enum RuleKind: String, Codable, CaseIterable, Sendable {
    case domain, domainSuffix, domainKeyword, ipCidr, processName, port
}

public struct Rule: Codable, Identifiable, Equatable, Sendable {
    public var id = UUID()
    public var kind: RuleKind
    public var value: String
    public var target: Target
    public var enabled = true

    public init(kind: RuleKind, value: String, target: Target, enabled: Bool = true) {
        self.kind = kind; self.value = value; self.target = target; self.enabled = enabled
    }

    enum CodingKeys: String, CodingKey { case id, kind, value, target, enabled }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        kind = try c.decode(RuleKind.self, forKey: .kind)
        value = try c.decode(String.self, forKey: .value)
        target = try c.decode(Target.self, forKey: .target)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }
}

/// Xray toggle and ordered routing rules.
public struct Settings: Codable, Equatable, Sendable {
    public var xrayOn = false
    public var rules: [Rule] = []
    public var autoBest = true
    public init() {}

    enum CodingKeys: String, CodingKey { case xrayOn, rules, autoBest }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        xrayOn = try c.decodeIfPresent(Bool.self, forKey: .xrayOn) ?? false
        let saved = try c.decodeIfPresent([Rule].self, forKey: .rules) ?? []
        // 0.2.0 saved these four defaults after the first settings change.
        // Remove only the untouched set; keep every custom or edited rule.
        let oldValues = ["100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        let oldDefaults = saved.count == oldValues.count && zip(saved, oldValues).allSatisfy { rule, value in
            rule.kind == .ipCidr && rule.value == value && rule.target == .direct && rule.enabled
        }
        rules = oldDefaults ? [] : saved
        autoBest = try c.decodeIfPresent(Bool.self, forKey: .autoBest) ?? true
    }
}

/// VLESS-сервер (то, что V2Box/Clash держат как «профиль»). Секреты хранятся только на диске с правами 0600.
/// Транспорт: tcp / ws / xhttp. Безопасность: reality / tls / none.
public struct XrayProfile: Codable, Equatable, Sendable, Identifiable {
    public var id = UUID()
    public var protocolType = "vless"
    public var name: String
    public var server: String
    public var port: Int
    public var uuid: String
    public var flow: String
    public var serverName: String
    public var publicKey: String
    public var shortId: String
    public var fingerprint: String
    public var network = "tcp"
    public var security = "reality"
    public var path = ""
    public var host = ""            // заголовок Host (ws) / host (xhttp)
    public var mode = ""            // xhttp: auto / packet-up / stream-up / stream-one
    public var alpn = ""            // через запятую: h2,http/1.1
    public var xhttpExtra = ""      // xhttp: сырой JSON «extra» из ссылки
    public var sourceURL: String?     // подписка, из которой получен сервер
    public var password = ""
    public var method = ""
    public var alterId = 0
    public var obfs = ""
    public var obfsPassword = ""
    public var upMbps = 0
    public var downMbps = 0
    public var privateKey = ""
    public var publicKeyPeer = ""
    public var preSharedKey = ""
    public var addresses: [String] = []
    public var allowedIPs: [String] = []
    public var mtu = 0
    public var keepalive = 0
    public var awgParameters: [String: String] = [:]
    public var awgPeerParameters: [String: String] = [:]
    public var dnsServer = ""
    public var allowInsecure = false

    public static let networks = ["tcp", "ws", "xhttp"]
    public static let securities = ["reality", "tls", "none"]

    /// sing-box не умеет xhttp — такие профили обслуживает xray-core как локальный SOCKS.
    public var needsSidecar: Bool { protocolType == "vless" && network == "xhttp" }
    public var supportsTCPPing: Bool { !["wireguard", "amneziawg", "hysteria2", "tuic"].contains(protocolType) }
    /// Короткая подпись для списка: «ws · tls».
    public var kind: String {
        ["wireguard", "amneziawg", "hysteria2", "tuic"].contains(protocolType)
            ? protocolType.uppercased() : "\(protocolType.uppercased()) · \(network)"
    }

    /// «Тот же сервер»: id не сравниваем — по нему дедуплицируем импорт.
    public static func == (a: XrayProfile, b: XrayProfile) -> Bool {
        a.protocolType == b.protocolType && a.name == b.name && a.server == b.server && a.port == b.port && a.uuid == b.uuid && a.flow == b.flow
            && a.serverName == b.serverName && a.publicKey == b.publicKey && a.shortId == b.shortId
            && a.fingerprint == b.fingerprint && a.network == b.network && a.security == b.security
            && a.path == b.path && a.host == b.host && a.mode == b.mode && a.alpn == b.alpn && a.xhttpExtra == b.xhttpExtra
            && a.password == b.password && a.method == b.method && a.alterId == b.alterId
            && a.obfs == b.obfs && a.obfsPassword == b.obfsPassword && a.upMbps == b.upMbps && a.downMbps == b.downMbps
            && a.privateKey == b.privateKey && a.publicKeyPeer == b.publicKeyPeer && a.preSharedKey == b.preSharedKey
            && a.addresses == b.addresses && a.allowedIPs == b.allowedIPs && a.mtu == b.mtu
            && a.keepalive == b.keepalive && a.awgParameters == b.awgParameters
            && a.awgPeerParameters == b.awgPeerParameters && a.dnsServer == b.dnsServer
            && a.allowInsecure == b.allowInsecure
    }

    // Старые файлы (без id и без транспорта) читаются как tcp+reality — так они и были созданы.
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        protocolType = try c.decodeIfPresent(String.self, forKey: .protocolType) ?? "vless"
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decode(String.self, forKey: .name); server = try c.decode(String.self, forKey: .server)
        port = try c.decode(Int.self, forKey: .port); uuid = try c.decode(String.self, forKey: .uuid)
        flow = try c.decodeIfPresent(String.self, forKey: .flow) ?? ""
        serverName = try c.decodeIfPresent(String.self, forKey: .serverName) ?? server
        publicKey = try c.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        shortId = try c.decodeIfPresent(String.self, forKey: .shortId) ?? ""
        fingerprint = try c.decodeIfPresent(String.self, forKey: .fingerprint) ?? "chrome"
        network = try c.decodeIfPresent(String.self, forKey: .network) ?? "tcp"
        security = try c.decodeIfPresent(String.self, forKey: .security) ?? "reality"
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? ""
        host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? ""
        alpn = try c.decodeIfPresent(String.self, forKey: .alpn) ?? ""
        xhttpExtra = try c.decodeIfPresent(String.self, forKey: .xhttpExtra) ?? ""
        sourceURL = try c.decodeIfPresent(String.self, forKey: .sourceURL)
        password = try c.decodeIfPresent(String.self, forKey: .password) ?? ""
        method = try c.decodeIfPresent(String.self, forKey: .method) ?? ""
        alterId = try c.decodeIfPresent(Int.self, forKey: .alterId) ?? 0
        obfs = try c.decodeIfPresent(String.self, forKey: .obfs) ?? ""
        obfsPassword = try c.decodeIfPresent(String.self, forKey: .obfsPassword) ?? ""
        upMbps = try c.decodeIfPresent(Int.self, forKey: .upMbps) ?? 0
        downMbps = try c.decodeIfPresent(Int.self, forKey: .downMbps) ?? 0
        privateKey = try c.decodeIfPresent(String.self, forKey: .privateKey) ?? ""
        publicKeyPeer = try c.decodeIfPresent(String.self, forKey: .publicKeyPeer) ?? ""
        preSharedKey = try c.decodeIfPresent(String.self, forKey: .preSharedKey) ?? ""
        addresses = try c.decodeIfPresent([String].self, forKey: .addresses) ?? []
        allowedIPs = try c.decodeIfPresent([String].self, forKey: .allowedIPs) ?? []
        mtu = try c.decodeIfPresent(Int.self, forKey: .mtu) ?? 0
        keepalive = try c.decodeIfPresent(Int.self, forKey: .keepalive) ?? 0
        awgParameters = try c.decodeIfPresent([String: String].self, forKey: .awgParameters) ?? [:]
        awgPeerParameters = try c.decodeIfPresent([String: String].self, forKey: .awgPeerParameters) ?? [:]
        dnsServer = try c.decodeIfPresent(String.self, forKey: .dnsServer) ?? ""
        allowInsecure = try c.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
    }

    public init(name: String, server: String, port: Int, uuid: String, flow: String = "",
                serverName: String, publicKey: String = "", shortId: String = "", fingerprint: String = "chrome",
                network: String = "tcp", security: String = "reality", path: String = "", host: String = "",
                mode: String = "", alpn: String = "", xhttpExtra: String = "") {
        self.name = name; self.server = server; self.port = port; self.uuid = uuid; self.flow = flow
        self.serverName = serverName; self.publicKey = publicKey; self.shortId = shortId; self.fingerprint = fingerprint
        self.network = network; self.security = security; self.path = path; self.host = host
        self.mode = mode; self.alpn = alpn; self.xhttpExtra = xhttpExtra
    }
}

public enum ForkError: Error, LocalizedError, Equatable {
    case importFailed(String)
    public var errorDescription: String? {
        switch self { case .importFailed(let m): return m }
    }
}

/// Несколько VLESS-серверов; `selected` — тот, что использует переключатель Xray.
public struct Profiles: Codable, Equatable, Sendable {
    public var items: [XrayProfile] = []
    public var selected: UUID?
    public var subscriptions: [String] = []

    public init() {}

    enum CodingKeys: String, CodingKey { case items, selected, subscriptions }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        items = try c.decodeIfPresent([XrayProfile].self, forKey: .items) ?? []
        selected = try c.decodeIfPresent(UUID.self, forKey: .selected)
        subscriptions = try c.decodeIfPresent([String].self, forKey: .subscriptions) ?? []
    }

    /// Replace only the servers belonging to this subscription, keeping stable IDs where possible.
    public mutating func sync(_ url: String, profiles fresh: [XrayProfile]) {
        guard !fresh.isEmpty else { return }
        if !subscriptions.contains(url) { subscriptions.append(url) }
        let old = items.filter { $0.sourceURL == url || ($0.sourceURL == nil && fresh.contains($0)) }
        var replacement: [XrayProfile] = []
        for var p in fresh {
            p.sourceURL = url
            if replacement.contains(p) { continue }
            if let match = old.first(where: { $0 == p }) { p.id = match.id }
            replacement.append(p)
        }
        let index = items.firstIndex { $0.sourceURL == url || ($0.sourceURL == nil && fresh.contains($0)) } ?? items.endIndex
        items.removeAll { $0.sourceURL == url || ($0.sourceURL == nil && fresh.contains($0)) }
        items.insert(contentsOf: replacement, at: min(index, items.count))
        if !items.contains(where: { $0.id == selected }) { selected = replacement.first?.id ?? items.first?.id }
    }

    public var active: XrayProfile? { items.first { $0.id == selected } ?? items.first }

    /// Добавляет новые (дубликаты по содержимому пропускает), возвращает сколько реально добавлено.
    @discardableResult
    public mutating func add(_ new: [XrayProfile]) -> Int {
        var n = 0
        for p in new where !items.contains(p) { items.append(p); n += 1 }
        if selected == nil || !items.contains(where: { $0.id == selected }) { selected = items.first?.id }
        return n
    }

    /// Сервер с наименьшей задержкой среди ответивших; nil, если не ответил никто.
    public func fastest(_ results: [UUID: PingResult]) -> XrayProfile? {
        items.compactMap { p -> (XrayProfile, Int)? in
            if case .ok(let ms)? = results[p.id] { return (p, ms) } else { return nil }
        }.min { $0.1 < $1.1 }?.0
    }

    public mutating func remove(_ id: UUID) {
        items.removeAll { $0.id == id }
        if selected == id || !items.contains(where: { $0.id == selected }) { selected = items.first?.id }
    }
}
