import XCTest
import Network
@testable import ForkCore

final class ProfilesTests: XCTestCase {
    func prof(_ n: String, _ host: String = "h", port: Int = 443) -> XrayProfile {
        XrayProfile(name: n, server: host, port: port, uuid: "u-\(n)", serverName: "sni", publicKey: "pk", shortId: "s")
    }

    func testAddDedupesAndSelectsFirst() {
        var ps = Profiles()
        XCTAssertEqual(ps.add([prof("a"), prof("b")]), 2)
        XCTAssertEqual(ps.add([prof("a"), prof("c")]), 1, "повтор по содержимому (id другой) пропускается")
        XCTAssertEqual(ps.items.count, 3); XCTAssertEqual(ps.active?.name, "a")
    }

    func testRemoveActiveFallsBack() {
        var ps = Profiles(); ps.add([prof("a"), prof("b")])
        ps.selected = ps.items[0].id; ps.remove(ps.items[0].id)
        XCTAssertEqual(ps.active?.name, "b"); XCTAssertEqual(ps.selected, ps.items[0].id)
        ps.remove(ps.items[0].id); XCTAssertNil(ps.active); XCTAssertNil(ps.selected)
    }

    func testFastestPicksMinimumAmongAnswered() {
        var ps = Profiles(); ps.add([prof("slow"), prof("fast"), prof("dead")])
        let r: [UUID: PingResult] = [ps.items[0].id: .ok(120), ps.items[1].id: .ok(35), ps.items[2].id: .failed("тайм-аут")]
        XCTAssertEqual(ps.fastest(r)?.name, "fast")
        XCTAssertNil(ps.fastest([ps.items[2].id: .failed("x")]), "никто не ответил — nil")
        XCTAssertNil(ps.fastest([:]))
    }

    func testOldXrayJsonWithoutIdDecodes() throws {
        let j = #"{"name":"n","server":"s","port":1,"uuid":"u","flow":"","serverName":"x","publicKey":"p","shortId":"","fingerprint":"chrome"}"#
        let p = try JSONDecoder().decode(XrayProfile.self, from: Data(j.utf8))
        XCTAssertEqual(p.server, "s")
    }

    func testOldSettingsFileKeepsRules() throws {
        let j = #"{"xrayOn":true,"rules":[{"id":"11111111-1111-1111-1111-111111111111","kind":"domain","value":"a.example","target":"direct","enabled":true}]}"#
        let s = try JSONDecoder().decode(Settings.self, from: Data(j.utf8))
        XCTAssertEqual(s.rules.count, 1); XCTAssertTrue(s.autoBest); XCTAssertTrue(s.xrayOn)
    }

    // MARK: импорт нескольких

    func testParseManyLinks() throws {
        let t = """
        vless://11111111-1111-1111-1111-111111111111@a.example:443?security=reality&sni=x&pbk=PK&sid=1&type=tcp#One
        мусор
        vless://22222222-2222-2222-2222-222222222222@b.example:444?security=reality&sni=x&pbk=PK&sid=2&type=tcp#Two
        vless://33333333-3333-3333-3333-333333333333@c.example:445?security=tls&type=grpc#Bad
        """
        XCTAssertEqual(try ProfileImport.parseMany(t).map(\.name), ["One", "Two"])
    }

    func testParseManyClashBothIndentStyles() throws {
        func item(_ ind: String, _ n: String, _ typ: String = "vless") -> String {
            """
            \(ind)- name: \(n)
            \(ind)  type: \(typ)
            \(ind)  server: \(n).example
            \(ind)  port: 443
            \(ind)  uuid: u-\(n)
            \(ind)  network: tcp
            \(ind)  alpn:
            \(ind)    - h2
            \(ind)  reality-opts:
            \(ind)    public-key: PK-\(n)
            \(ind)    short-id: ab
            """
        }
        for ind in ["", "  "] {
            let y = "proxies:\n" + [item(ind, "a"), item(ind, "ss", "ss"), item(ind, "b")].joined(separator: "\n") + "\nrules:\n- MATCH,PROXY\n"
            let ps = try ProfileImport.parseMany(y)
            XCTAssertEqual(ps.map(\.name), ["a", "b"], "отступ «\(ind)»")
            XCTAssertEqual(ps[1].publicKey, "PK-b"); XCTAssertEqual(ps[0].server, "a.example")
        }
    }

    func testParseManyNothingUsefulThrows() {
        XCTAssertThrowsError(try ProfileImport.parseMany("hello"))
    }

    func testBase64SubscriptionAndSync() throws {
        let link = "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=reality&pbk=PK&type=tcp#One"
        let encoded = Data(link.utf8).base64EncodedString()
        let imported = try ProfileImport.parseMany(encoded)
        XCTAssertEqual(imported.map(\.name), ["One"])
        var ps = Profiles()
        ps.sync("https://example.com/sub/secret", profiles: imported)
        let id = try XCTUnwrap(ps.active?.id)
        ps.sync("https://example.com/sub/secret", profiles: imported)
        XCTAssertEqual(ps.items.count, 1)
        XCTAssertEqual(ps.active?.id, id)
        XCTAssertEqual(ps.subscriptions.count, 1)
        let saved = try JSONEncoder().encode(ps)
        XCTAssertEqual(try JSONDecoder().decode(Profiles.self, from: saved), ps)
    }

    func testVergeRemoteRegistry() {
        let registry = """
        items:
        - uid: local
          type: merge
          url: https://example.com/ignore
        - uid: remote
          type: remote
          file: remote.yaml
          url: https://example.com/sub/secret
        - uid: unsafe
          type: remote
          url: http://example.com/sub
        """
        XCTAssertEqual(SubscriptionImport.vergeRemoteURLs(registry), ["https://example.com/sub/secret"])
    }

    // MARK: пинг

    func testPingLocalListenerAndRefusedPort() async throws {
        let listener = try NWListener(using: .tcp, on: .any)
        listener.newConnectionHandler = { $0.cancel() }
        let q = DispatchQueue(label: "t"); listener.start(queue: q)
        var port = 0
        for _ in 0..<50 { if let p = listener.port?.rawValue, p != 0 { port = Int(p); break }; try await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertGreaterThan(port, 0)
        if case .ok(let ms) = await TCPPing.measure(host: "127.0.0.1", port: port) { XCTAssertLessThan(ms, 1000) }
        else { XCTFail("локальный слушатель должен отвечать") }
        listener.cancel()
        try await Task.sleep(nanoseconds: 200_000_000)
        if case .ok = await TCPPing.measure(host: "127.0.0.1", port: port, timeout: 1) { XCTFail("порт закрыт, ответа быть не должно") }
        if case .ok = await TCPPing.measure(host: "127.0.0.1", port: 0) { XCTFail("порт 0 неверен") }
    }
}
