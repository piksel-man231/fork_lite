import XCTest
@testable import ForkCore

final class ConfigBuilderTests: XCTestCase {
    let profile = XrayProfile(name: "test", server: "example.com", port: 443, uuid: "00000000-0000-0000-0000-000000000000", serverName: "example.com", publicKey: "key", shortId: "id")

    func testXrayAndDirectRules() {
        var settings = Settings(); settings.xrayOn = true
        settings.rules = [Rule(kind: .domainSuffix, value: "local.example", target: .direct)]
        let config = ConfigBuilder(settings: settings, xray: profile).build()
        let outbounds = config["outbounds"] as! [[String: Any]]
        XCTAssertEqual(outbounds.compactMap { $0["tag"] as? String }, ["direct", "xray"])
        let route = config["route"] as! [String: Any]
        XCTAssertEqual(route["final"] as? String, "xray")
        let rules = route["rules"] as! [[String: Any]]
        XCTAssertTrue(rules.contains { ($0["domain_suffix"] as? [String]) == ["local.example"] && ($0["outbound"] as? String) == "direct" })
    }

    func testNoProfileDoesNotStartCore() {
        var settings = Settings(); settings.xrayOn = true
        XCTAssertFalse(ConfigBuilder(settings: settings, xray: nil).needsCore)
    }
}
