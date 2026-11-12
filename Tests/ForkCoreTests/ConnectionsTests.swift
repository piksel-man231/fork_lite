import XCTest
@testable import ForkCore

final class ConnectionsTests: XCTestCase {
    func snap(up: Int64, down: Int64) -> ConnectionsSnapshot {
        let j = """
        {"downloadTotal":\(down),"uploadTotal":\(up),"connections":[{"id":"a1","upload":\(up),"download":\(down),
         "start":"2026-10-19T17:14:24.123456+03:00","chains":["xray"],"rule":"domain_suffix=example.com","rulePayload":"",
         "metadata":{"network":"tcp","type":"mixed/socks5","sourceIP":"127.0.0.1","sourcePort":"58908",
         "destinationIP":"","destinationPort":"443","host":"www.example.com","processPath":"/usr/bin/curl"}}]}
        """
        return try! JSONDecoder().decode(ConnectionsSnapshot.self, from: Data(j.utf8))
    }

    func testSpeedIsDeltaOverTime_andRowFields() {
        var t = ConnectionTracker(); let t0 = Date()
        var rows = t.update(snap(up: 1000, down: 10_000), now: t0)
        XCTAssertEqual(rows[0].downSpeed, 0, "первый опрос — скорости ещё нет")
        rows = t.update(snap(up: 3000, down: 30_000), now: t0.addingTimeInterval(2))
        XCTAssertEqual(rows[0].upSpeed, 1000); XCTAssertEqual(rows[0].downSpeed, 10_000)
        XCTAssertEqual(t.downSpeed, 10_000)
        XCTAssertEqual(rows[0].host, "www.example.com:443"); XCTAssertEqual(rows[0].process, "curl")
        XCTAssertEqual(rows[0].domain, "www.example.com")
        XCTAssertNil(rows[0].ipCIDR)
        XCTAssertEqual(rows[0].outbound, "xray"); XCTAssertEqual(rows[0].network, "TCP")
        XCTAssertNotNil(rows[0].start)
    }

    func testProcessAndRuleCleanup() {
        XCTAssertEqual(ConnectionTracker.processName("/usr/bin/curl (kirill)"), "curl")
        XCTAssertEqual(ConnectionTracker.processName("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome (kirill)"), "Google Chrome")
        XCTAssertEqual(ConnectionTracker.processName(""), "")
        XCTAssertEqual(ConnectionTracker.ruleText("domain_suffix=example.com => route(xray)", ""), "domain_suffix=example.com")
        XCTAssertEqual(ConnectionTracker.ruleText("final", ""), "final")
    }

    func testCounterResetNeverGivesNegativeSpeed() {
        var t = ConnectionTracker(); let t0 = Date()
        _ = t.update(snap(up: 5000, down: 5000), now: t0)
        let r = t.update(snap(up: 10, down: 10), now: t0.addingTimeInterval(1))
        XCTAssertEqual(r[0].downSpeed, 0)
    }

    func testServiceConnectionsRequireTransportProcessAndDirectOutbound() {
        var tracker = ConnectionTracker()
        var row = tracker.update(snap(up: 12, down: 34))[0]
        XCTAssertEqual(row.totalBytes, 46)
        XCTAssertFalse(row.isService)
        row.process = "xray"
        XCTAssertFalse(row.isService, "имя процесса само по себе не означает внешний транспорт")
        row.outbound = "direct"
        XCTAssertTrue(row.isService)
        row.process = "xray"
        XCTAssertTrue(row.isService)
        row.process = "Vivaldi Helper"
        XCTAssertFalse(row.isService, "прямые соединения приложений остаются видимыми")
    }

    func testEqualStartDatesHaveStableOrderAcrossPolls() throws {
        var snapshot = snap(up: 0, down: 0)
        var first = snapshot.connections[0]
        first.id = "a"
        var second = first
        second.id = "b"
        var tracker = ConnectionTracker()
        snapshot.connections = [second, first]
        XCTAssertEqual(tracker.update(snapshot).map(\.id), ["a", "b"])
        snapshot.connections.reverse()
        XCTAssertEqual(tracker.update(snapshot).map(\.id), ["a", "b"])
    }

    func testRulesNewestFirstAndChainReversed() {
        let j = """
        {"downloadTotal":0,"uploadTotal":0,"connections":[
         {"id":"old","chains":["xray","sel"],"start":"2026-10-19T10:00:00Z","metadata":{"destinationIP":"1.1.1.1","destinationPort":"53"}},
         {"id":"new","chains":["direct"],"start":"2026-10-19T11:00:00Z","metadata":{"destinationIP":"2.2.2.2","destinationPort":"443"}}]}
        """
        var t = ConnectionTracker()
        let rows = t.update(try! JSONDecoder().decode(ConnectionsSnapshot.self, from: Data(j.utf8)))
        XCTAssertEqual(rows.map(\.id), ["new", "old"])
        XCTAssertEqual(rows[1].outbound, "sel → xray")
        XCTAssertEqual(rows[0].host, "2.2.2.2:443", "без домена показываем ip:порт")
        XCTAssertNil(rows[0].domain)
        XCTAssertEqual(rows[0].ipCIDR, "2.2.2.2/32")
    }

    func testIPv6ConnectionOffersExactAddressRule() throws {
        let json = #"{"downloadTotal":0,"uploadTotal":0,"connections":[{"id":"v6","metadata":{"destinationIP":"2001:db8::1","destinationPort":"443","host":""}}]}"#
        var tracker = ConnectionTracker()
        let row = try XCTUnwrap(tracker.update(JSONDecoder().decode(ConnectionsSnapshot.self, from: Data(json.utf8))).first)
        XCTAssertNil(row.domain)
        XCTAssertEqual(row.ipCIDR, "2001:db8::1/128")
    }
}

