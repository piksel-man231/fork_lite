import Foundation
import ForkCore

/// Локальный xray-core для профилей с транспортом xhttp (sing-box его не умеет): SOCKS на 127.0.0.1.
/// Работает от имени пользователя; его трафик в TUN отправляется «напрямую» правилом по имени процесса.
final class XraySidecar: @unchecked Sendable {
    static let shared = XraySidecar()
    private let lock = NSLock()
    private var proc: Process?

    static var binary: String? {
        let bundled = Bundle.main.resourcePath.map { $0 + "/vendor/bin/xray" }
        return ([bundled].compactMap { $0 } + ["/opt/homebrew/bin/xray", "/usr/local/bin/xray"])
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    func start(_ profile: XrayProfile) throws {
        stop()
        guard let bin = Self.binary else { throw ForkError.importFailed("В приложении нет xray для xhttp") }
        let url = Store.dir.appendingPathComponent("xray-sidecar.json")
        try XrayConfigBuilder.json(profile).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        let p = Process(); p.executableURL = URL(fileURLWithPath: bin); p.arguments = ["run", "-c", url.path]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        lock.lock(); proc = p; lock.unlock()
    }

    var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return proc?.isRunning ?? false }

    func stop() {
        lock.lock(); let p = proc; proc = nil; lock.unlock()
        if let p, p.isRunning { p.terminate(); p.waitUntilExit() }
    }
}
