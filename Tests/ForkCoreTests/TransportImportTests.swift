import XCTest
@testable import ForkCore

final class TransportImportTests: XCTestCase {
    func testWsTlsLink() throws {
        let p = try ProfileImport.parse("vless://11111111-1111-1111-1111-111111111111@cdn.example:443?type=ws&security=tls&sni=front.example&host=origin.example&path=%2Fws%3Fed%3D2048&fp=firefox&alpn=h2%2Chttp%2F1.1&encryption=none#WS")
        XCTAssertEqual([p.network, p.security, p.serverName, p.host, p.path, p.fingerprint, p.alpn],
                       ["ws", "tls", "front.example", "origin.example", "/ws?ed=2048", "firefox", "h2,http/1.1"])
        XCTAssertEqual(p.kind, "ws · tls"); XCTAssertFalse(p.needsSidecar)
    }

    func testXhttpRealityLinkNeedsSidecarAndDropsFlow() throws {
        let p = try ProfileImport.parse("vless://22222222-2222-2222-2222-222222222222@x.example:443?type=xhttp&security=reality&sni=www.amd.com&pbk=PK&sid=ab&path=%2Fx&mode=packet-up&flow=xtls-rprx-vision&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#X")
        XCTAssertEqual(p.network, "xhttp"); XCTAssertEqual(p.mode, "packet-up"); XCTAssertEqual(p.path, "/x")
        XCTAssertEqual(p.xhttpExtra, #"{"xPaddingBytes":"100-1000"}"#)
        XCTAssertEqual(p.flow, "", "vision не работает поверх xhttp"); XCTAssertTrue(p.needsSidecar)
    }

    func testSplithttpAliasAndDefaults() throws {
        let p = try ProfileImport.parse("vless://33333333-3333-3333-3333-333333333333@x.example:443?type=splithttp&security=none")
        XCTAssertEqual(p.network, "xhttp"); XCTAssertEqual(p.path, "/", "путь по умолчанию «/»"); XCTAssertEqual(p.serverName, "x.example")
    }

    func testRejects() {
        XCTAssertThrowsError(try ProfileImport.parse("vless://u@h:1?type=grpc&security=tls"))
        XCTAssertThrowsError(try ProfileImport.parse("vless://u@h:1?type=tcp&security=reality"), "reality без pbk")
        XCTAssertThrowsError(try ProfileImport.parse("vless://u@h:1?type=ws&security=tls&encryption=mlkem768x25519plus"))
        XCTAssertThrowsError(try ProfileImport.parse("vless://u@h:1?type=ws&security=xtls"))
        XCTAssertThrowsError(try ProfileImport.parse("vless://u@h:1?type=ws&security=reality&pbk=PK"), "reality поверх ws невалиден")
    }

    func testClashWsOptsNested() throws {
        let y = """
        proxies:
          - name: w
            type: vless
            server: cdn.example
            port: 443
            uuid: u-w
            network: ws
            tls: true
            servername: front.example
            client-fingerprint: chrome
            ws-opts:
              path: /socket
              headers:
                Host: origin.example
        """
        let p = try ProfileImport.parse(y)
        XCTAssertEqual([p.network, p.security, p.path, p.host, p.serverName], ["ws", "tls", "/socket", "origin.example", "front.example"])
    }

    func testClashXhttpReality() throws {
        let y = """
        proxies:
        - name: xh
          type: vless
          server: x.example
          port: 443
          uuid: u-x
          network: xhttp
          tls: true
          servername: www.amd.com
          reality-opts:
            public-key: PK
            short-id: ab
          xhttp-opts:
            path: /xh
            host: h.example
            mode: stream-up
        """
        let p = try ProfileImport.parse(y)
        XCTAssertEqual([p.network, p.security, p.path, p.host, p.mode, p.publicKey], ["xhttp", "reality", "/xh", "h.example", "stream-up", "PK"])
    }

    func testLegacyProfileJsonIsTcpReality() throws {
        let j = #"{"name":"n","server":"s","port":1,"uuid":"u","flow":"xtls-rprx-vision","serverName":"x","publicKey":"p","shortId":"","fingerprint":"chrome"}"#
        let p = try JSONDecoder().decode(XrayProfile.self, from: Data(j.utf8))
        XCTAssertEqual([p.network, p.security], ["tcp", "reality"])
    }
}
