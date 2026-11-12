import Foundation

/// Файлы приложения в ~/Library/Application Support/Fork Lite. Профиль xray — с правами 0600 (там uuid и ключи).
public enum Store {
    public static var dir: URL {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Fork Lite")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return d
    }
    public static var configURL: URL { dir.appendingPathComponent("config.json") }
    public static var awgConfigURL: URL { dir.appendingPathComponent("awg.conf") }

    public static func load<T: Decodable>(_ name: String, as: T.Type = T.self) -> T? {
        guard let d = try? Data(contentsOf: dir.appendingPathComponent(name)) else { return nil }
        return try? JSONDecoder().decode(T.self, from: d)
    }

    public static func save<T: Encodable>(_ value: T, name: String) {
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let d = try? enc.encode(value) else { return }
        let url = dir.appendingPathComponent(name)
        try? d.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public static func writeConfig(_ data: Data) throws {
        try data.write(to: configURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    }
}

