import Foundation

enum Shell {
    /// Запускает команду, ждёт, возвращает (код, вывод). Вызывать не из главного потока.
    static func run(_ path: String, _ args: [String], stdin: String? = nil) -> (code: Int32, out: String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: path); p.arguments = args
        let out = Pipe(); p.standardOutput = out; p.standardError = out
        var inPipe: Pipe?
        if stdin != nil { inPipe = Pipe(); p.standardInput = inPipe }
        do { try p.run() } catch { return (-1, "\(error)") }
        if let s = stdin, let ip = inPipe {
            ip.fileHandleForWriting.write(Data(s.utf8)); try? ip.fileHandleForWriting.close()
        }
        let d = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        return (p.terminationStatus, String(decoding: d, as: UTF8.self))
    }

    static func sudo(_ script: String, stdin: String? = nil) -> (code: Int32, out: String) {
        run("/usr/bin/sudo", ["-n", "/usr/local/fork_lite/\(script)"], stdin: stdin)
    }

    static func tail(_ path: String, bytes: Int = 6000) -> String {
        guard let h = FileHandle(forReadingAtPath: path) else { return "" }
        defer { try? h.close() }
        let size = (try? h.seekToEnd()) ?? 0
        try? h.seek(toOffset: size > UInt64(bytes) ? size - UInt64(bytes) : 0)
        return String(decoding: (try? h.readToEnd()) ?? Data(), as: UTF8.self)
    }
}
