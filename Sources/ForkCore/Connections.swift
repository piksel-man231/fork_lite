import Foundation
import Network

// Модели ответа Clash API sing-box: GET /connections.
public struct ConnectionsSnapshot: Decodable, Sendable {
    public var downloadTotal: Int64
    public var uploadTotal: Int64
    public var connections: [Conn]

    public struct Conn: Decodable, Sendable {
        public var id: String
        public var upload: Int64
        public var download: Int64
        public var start: String
        public var chains: [String]
        public var rule: String
        public var rulePayload: String
        public var metadata: Meta

        enum CodingKeys: String, CodingKey { case id, upload, download, start, chains, rule, rulePayload, metadata }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            upload = try c.decodeIfPresent(Int64.self, forKey: .upload) ?? 0
            download = try c.decodeIfPresent(Int64.self, forKey: .download) ?? 0
            start = try c.decodeIfPresent(String.self, forKey: .start) ?? ""
            chains = try c.decodeIfPresent([String].self, forKey: .chains) ?? []
            rule = try c.decodeIfPresent(String.self, forKey: .rule) ?? ""
            rulePayload = try c.decodeIfPresent(String.self, forKey: .rulePayload) ?? ""
            metadata = try c.decode(Meta.self, forKey: .metadata)
        }
    }

    public struct Meta: Decodable, Sendable {
        public var network: String
        public var type: String
        public var sourceIP: String
        public var destinationIP: String
        public var destinationPort: String
        public var host: String
        public var processPath: String

        enum CodingKeys: String, CodingKey { case network, type, sourceIP, destinationIP, destinationPort, host, processPath }
        public init(from d: Decoder) throws {
            let c = try d.container(keyedBy: CodingKeys.self)
            func str(_ k: CodingKeys) -> String {
                if let s = try? c.decodeIfPresent(String.self, forKey: k) { return s }
                if let i = try? c.decodeIfPresent(Int.self, forKey: k) { return String(i) }
                return ""
            }
            network = str(.network); type = str(.type); sourceIP = str(.sourceIP)
            destinationIP = str(.destinationIP); destinationPort = str(.destinationPort)
            host = str(.host); processPath = str(.processPath)
        }
    }
}

/// Строка таблицы соединений.
public struct ConnectionRow: Identifiable, Equatable, Sendable {
    public var id: String
    public var host: String          // домен, а если его нет — ip:порт
    public var domain: String?       // исходный домен без порта; nil для IP-соединений
    public var ipCIDR: String?       // точный адрес назначения (/32 или /128)
    public var process: String
    public var network: String       // TCP / UDP
    public var outbound: String      // цепочка выходов: xray / direct
    public var rule: String
    public var upload: Int64, download: Int64
    public var upSpeed: Int64, downSpeed: Int64   // байт/с
    public var start: Date?

    public var totalBytes: Int64 { download + upload }
    public var startedAt: Date { start ?? .distantPast }

    /// Внешние соединения транспорта уже представлены строками приложений внутри туннеля.
    public var isService: Bool {
        outbound == "direct" && ["xray", "amneziawg-go"].contains(process)
    }
}

/// Считает скорости как разницу байтов между опросами (Clash API отдаёт только накопленные значения).
public struct ConnectionTracker {
    /// sing-box отдаёт «/usr/bin/curl (kirill)» — оставляем имя файла без пользователя.
    static func processName(_ raw: String) -> String {
        var p = Substring(raw)
        if p.hasSuffix(")"), let open = p.lastIndex(of: "(") { p = p[..<open] }
        return (String(p).trimmingCharacters(in: .whitespaces) as NSString).lastPathComponent
    }

    /// Strip the route suffix from a Clash API rule; final rule stays final.
    static func ruleText(_ rule: String, _ payload: String) -> String {
        let r = rule.components(separatedBy: " => ").first ?? rule
        return payload.isEmpty ? r : "\(r) \(payload)"
    }

    private var last: [String: (up: Int64, down: Int64)] = [:]
    private var lastTime: Date?
    public private(set) var uploadTotal: Int64 = 0, downloadTotal: Int64 = 0
    public private(set) var upSpeed: Int64 = 0, downSpeed: Int64 = 0

    public init() {}

    public mutating func update(_ snap: ConnectionsSnapshot, now: Date = Date()) -> [ConnectionRow] {
        let dt = lastTime.map { max(now.timeIntervalSince($0), 0.001) }
        var next: [String: (Int64, Int64)] = [:]
        var rows: [ConnectionRow] = []
        let iso = ISO8601DateFormatter(); iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let isoPlain = ISO8601DateFormatter()
        for c in snap.connections {
            let prev = last[c.id]
            let up = dt != nil && prev != nil ? Int64(Double(max(c.upload - prev!.up, 0)) / dt!) : 0
            let down = dt != nil && prev != nil ? Int64(Double(max(c.download - prev!.down, 0)) / dt!) : 0
            next[c.id] = (c.upload, c.download)
            let m = c.metadata
            let host = !m.host.isEmpty ? m.host : "\(m.destinationIP):\(m.destinationPort)"
            let hostIsIP = IPv4Address(m.host) != nil || IPv6Address(m.host) != nil
            let domain = m.host.isEmpty || m.host.contains(":") || hostIsIP ? nil : m.host
            let ip = [m.destinationIP, m.host].first { IPv4Address($0) != nil || IPv6Address($0) != nil }
            let ipCIDR = ip.map { "\($0)/\(IPv4Address($0) != nil ? 32 : 128)" }
            rows.append(ConnectionRow(
                id: c.id, host: m.host.isEmpty ? host : "\(m.host):\(m.destinationPort)",
                domain: domain, ipCIDR: ipCIDR,
                process: Self.processName(m.processPath), network: m.network.uppercased(),
                outbound: c.chains.reversed().joined(separator: " → "),
                rule: Self.ruleText(c.rule, c.rulePayload),
                upload: c.upload, download: c.download, upSpeed: up, downSpeed: down,
                start: iso.date(from: c.start) ?? isoPlain.date(from: c.start)))
        }
        upSpeed = rows.reduce(0) { $0 + $1.upSpeed }; downSpeed = rows.reduce(0) { $0 + $1.downSpeed }
        uploadTotal = snap.uploadTotal; downloadTotal = snap.downloadTotal
        last = next; lastTime = now
        return rows.sorted {
            $0.startedAt == $1.startedAt ? $0.id < $1.id : $0.startedAt > $1.startedAt
        }
    }
}

/// Клиент Clash API (только localhost, с секретом).
public struct ClashAPI: Sendable {
    public let port: Int, secret: String
    public init(port: Int, secret: String) { self.port = port; self.secret = secret }

    func request(_ path: String, method: String = "GET") -> URLRequest {
        var r = URLRequest(url: URL(string: "http://127.0.0.1:\(port)\(path)")!, timeoutInterval: 3)
        r.httpMethod = method
        r.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        return r
    }

    public func connections() async throws -> ConnectionsSnapshot {
        let (d, _) = try await URLSession.shared.data(for: request("/connections"))
        return try JSONDecoder().decode(ConnectionsSnapshot.self, from: d)
    }

    /// id == nil → закрыть все.
    public func close(_ id: String? = nil) async {
        _ = try? await URLSession.shared.data(for: request("/connections" + (id.map { "/\($0)" } ?? ""), method: "DELETE"))
    }
}
