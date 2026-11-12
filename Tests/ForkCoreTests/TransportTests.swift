import XCTest
import Darwin
@testable import ForkCore

final class TransportConfigTests: XCTestCase {
    func profile(_ n: String, _ sec: String, flow: String = "", alpn: String = "") -> XrayProfile {
        XrayProfile(name: "t", server: "s.example.com", port: 443, uuid: "11111111-1111-1111-1111-111111111111", flow: flow,
                    serverName: "front.example", publicKey: sec == "reality" ? "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" : "",
                    shortId: "ab", network: n, security: sec, path: n == "tcp" ? "" : "/p", host: "h.example", mode: "auto", alpn: alpn)
    }
    func xrayOut(_ p: XrayProfile, mode: RunMode = .tun) -> [String: Any] {
        var s = Settings(); s.xrayOn = true; s.rules = []
        let b = ConfigBuilder(settings: s, xray: p, mode: mode).build()
        return (b["outbounds"] as! [[String: Any]]).first { $0["tag"] as? String == "xray" }!
    }

    func testWsTlsOutbound() {
        let o = xrayOut(profile("ws", "tls", alpn: "h2, http/1.1"))
        XCTAssertEqual(o["type"] as? String, "vless")
        let t = o["transport"] as! [String: Any]
        XCTAssertEqual(t["type"] as? String, "ws"); XCTAssertEqual(t["path"] as? String, "/p")
        XCTAssertEqual((t["headers"] as! [String: String])["Host"], "h.example")
        let tls = o["tls"] as! [String: Any]
        XCTAssertEqual(tls["alpn"] as? [String], ["h2", "http/1.1"]); XCTAssertNil(tls["reality"])
        XCTAssertNil(o["flow"])
    }

    func testTcpRealityKeepsFlowAndReality() {
        let o = xrayOut(profile("tcp", "reality", flow: "xtls-rprx-vision"))
        XCTAssertEqual(o["flow"] as? String, "xtls-rprx-vision"); XCTAssertNil(o["transport"])
        XCTAssertNotNil((o["tls"] as! [String: Any])["reality"])
    }

    func testSecurityNoneHasNoTls() { XCTAssertNil(xrayOut(profile("ws", "none"))["tls"]) }

    func testXhttpGoesThroughSidecarSocks() {
        let o = xrayOut(profile("xhttp", "tls"))
        XCTAssertEqual(o["type"] as? String, "socks"); XCTAssertEqual(o["server_port"] as? Int, ConfigBuilder.sidecarPort)
        var s = Settings(); s.xrayOn = true; s.rules = []
        let b = ConfigBuilder(settings: s, xray: profile("xhttp", "tls"), ).build()
        let rr = (b["route"] as! [String: Any])["rules"] as! [[String: Any]]
        let i = rr.firstIndex { ($0["process_name"] as? [String]) == ["xray"] }
        XCTAssertNotNil(i, "трафик сопроцесса xray должен идти напрямую, иначе петля через TUN")
        XCTAssertEqual(rr[i!]["outbound"] as? String, "direct")
    }

    func testXrayClientConfigShapes() throws {
        var p = profile("xhttp", "reality"); p.xhttpExtra = #"{"xPaddingBytes":"100-1000"}"#; p.mode = ""
        let c = XrayConfigBuilder.build(p, socksPort: 19999)
        let out = (c["outbounds"] as! [[String: Any]])[0]
        let st = out["streamSettings"] as! [String: Any]
        XCTAssertEqual(st["network"] as? String, "xhttp"); XCTAssertEqual(st["security"] as? String, "reality")
        let x = st["xhttpSettings"] as! [String: Any]
        XCTAssertEqual(x["mode"] as? String, "auto", "пустой mode → auto"); XCTAssertEqual(x["host"] as? String, "h.example")
        XCTAssertEqual((x["extra"] as! [String: Any])["xPaddingBytes"] as? String, "100-1000")
        XCTAssertEqual(((c["inbounds"] as! [[String: Any]])[0])["port"] as? Int, 19999)
    }

    func run(_ bin: String, _ args: [String]) throws -> (Int32, String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: bin); p.arguments = args
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        try p.run(); p.waitUntilExit()
        return (p.terminationStatus, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }

    /// Все комбинации транспорт × безопасность обязаны проходить настоящие валидаторы sing-box и xray.
    func testRealValidatorsAcceptAllCombos() throws {
        let sb = "/opt/homebrew/bin/sing-box", xr = "/opt/homebrew/bin/xray"
        try XCTSkipIf(!FileManager.default.isExecutableFile(atPath: sb) || !FileManager.default.isExecutableFile(atPath: xr), "нужны sing-box и xray")
        for net in XrayProfile.networks { for sec in XrayProfile.securities {
            if net == "ws" && sec == "reality" { continue }   // невалидная в xray комбинация, импорт её отвергает
            let p = profile(net, sec, flow: net == "tcp" ? "xtls-rprx-vision" : "")
            let tmp = FileManager.default.temporaryDirectory
            let f1 = tmp.appendingPathComponent("fk-sb-\(UUID()).json"), f2 = tmp.appendingPathComponent("fk-xr-\(UUID()).json")
            defer { try? FileManager.default.removeItem(at: f1); try? FileManager.default.removeItem(at: f2) }
            var s = Settings(); s.xrayOn = true; s.rules = []
            try ConfigBuilder(settings: s, xray: p, ).json().write(to: f1)
            let r1 = try run(sb, ["check", "-c", f1.path]); XCTAssertEqual(r1.0, 0, "sing-box \(net)+\(sec): \(r1.1)")
            if p.needsSidecar || net == "ws" {   // xray-клиент нужен/полезен только для них; проверим и ws для надёжности
                try XrayConfigBuilder.json(p).write(to: f2)
                let r2 = try run(xr, ["run", "-test", "-c", f2.path]); XCTAssertEqual(r2.0, 0, "xray \(net)+\(sec): \(r2.1)")
            }
        } }
    }
}

/// Живой прогон на loopback: настоящий xray-СЕРВЕР принимает наши клиентские конфиги, трафик доходит до HTTP-цели.
final class TransportLoopbackE2ETests: XCTestCase {
    let uuid = "5783a3e7-e373-51cd-8642-c83782b807c5"
    var procs: [Process] = []
    override func tearDown() { procs.forEach { $0.terminate() }; procs = [] }

    func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0); defer { Darwin.close(fd) }
        var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = 0
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: a.sin_port))
    }

    func waitPort(_ port: Int, timeout: TimeInterval = 8) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            let fd = socket(AF_INET, SOCK_STREAM, 0); defer { Darwin.close(fd) }
            var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1"); a.sin_port = UInt16(port).bigEndian
            let ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } } == 0
            if ok { return true }
            Thread.sleep(forTimeInterval: 0.15)
        }
        return false
    }

    @discardableResult
    func start(_ bin: String, _ args: [String]) throws -> Process {
        let p = Process(); p.executableURL = URL(fileURLWithPath: bin); p.arguments = args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); procs.append(p); return p
    }

    func serverConfig(port: Int, stream: [String: Any]) -> [String: Any] {
        ["log": ["loglevel": "warning"],
         "inbounds": [["listen": "127.0.0.1", "port": port, "protocol": "vless",
                       "settings": ["clients": [["id": uuid]], "decryption": "none"], "streamSettings": stream] as [String: Any]],
         "outbounds": [["protocol": "freedom"]]]
    }

    func write(_ obj: [String: Any], _ name: String) throws -> String {
        let f = NSTemporaryDirectory() + name
        try JSONSerialization.data(withJSONObject: obj).write(to: URL(fileURLWithPath: f)); return f
    }

    /// Запускает sing-box (proxy-режим, final=xray) с профилем и качает файл с цели через его SOCKS.
    func fetchViaSingBox(_ profile: XrayProfile, target: Int) throws -> String {
        var s = Settings(); s.xrayOn = true; s.rules = []
        let mix = freePort()
        let cfg = NSTemporaryDirectory() + "fk-e2e-sb-\(mix).json"
        try ConfigBuilder(settings: s, xray: profile, mode: .proxy(port: mix)).json().write(to: URL(fileURLWithPath: cfg))
        try start("/opt/homebrew/bin/sing-box", ["run", "-c", cfg])
        XCTAssertTrue(waitPort(mix), "sing-box не поднялся")
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["curl", "-s", "-m", "12", "--noproxy", "", "--socks5-hostname", "127.0.0.1:\(mix)", "http://127.0.0.1:\(target)/ok.txt"]
        let pipe = Pipe(); p.standardOutput = pipe; try p.run(); p.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    func needTools() throws -> Int {
        try XCTSkipIf(!FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/xray")
                      || !FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/sing-box"), "нужны sing-box и xray")
        let dir = NSTemporaryDirectory() + "fk-target"; try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try "FORK-OK".write(toFile: dir + "/ok.txt", atomically: true, encoding: .utf8)
        let target = freePort()
        try start("/usr/bin/python3", ["-m", "http.server", "\(target)", "--bind", "127.0.0.1", "--directory", dir])
        XCTAssertTrue(waitPort(target), "цель не поднялась")
        return target
    }

    func testWsThroughSingBoxToRealXrayServer() throws {
        let target = try needTools(), port = freePort()
        let srv = try write(serverConfig(port: port, stream: ["network": "ws", "security": "none", "wsSettings": ["path": "/fk"]]), "fk-ws-srv.json")
        try start("/opt/homebrew/bin/xray", ["run", "-c", srv]); XCTAssertTrue(waitPort(port), "xray-сервер не поднялся")
        let p = XrayProfile(name: "ws", server: "127.0.0.1", port: port, uuid: uuid, serverName: "127.0.0.1",
                            network: "ws", security: "none", path: "/fk")
        XCTAssertEqual(try fetchViaSingBox(p, target: target), "FORK-OK")
    }

    func testXhttpThroughSidecarAndSingBoxToRealXrayServer() throws {
        let target = try needTools(), port = freePort()
        let srv = try write(serverConfig(port: port, stream: ["network": "xhttp", "security": "none", "xhttpSettings": ["path": "/fk", "mode": "auto"]]), "fk-xh-srv.json")
        try start("/opt/homebrew/bin/xray", ["run", "-c", srv]); XCTAssertTrue(waitPort(port), "xray-сервер не поднялся")
        let p = XrayProfile(name: "xh", server: "127.0.0.1", port: port, uuid: uuid, serverName: "127.0.0.1",
                            network: "xhttp", security: "none", path: "/fk", mode: "auto")
        let side = NSTemporaryDirectory() + "fk-xh-side.json"
        try XrayConfigBuilder.json(p).write(to: URL(fileURLWithPath: side))
        try start("/opt/homebrew/bin/xray", ["run", "-c", side]); XCTAssertTrue(waitPort(ConfigBuilder.sidecarPort), "сопроцесс xray не поднялся")
        XCTAssertEqual(try fetchViaSingBox(p, target: target), "FORK-OK")
    }
}
