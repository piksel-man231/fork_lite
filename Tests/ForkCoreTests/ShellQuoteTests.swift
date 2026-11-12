import XCTest
@testable import ForkCore

final class ShellQuoteTests: XCTestCase {
    func run(_ cmd: String) -> String {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = ["-c", cmd]
        let pipe = Pipe(); p.standardOutput = pipe; try? p.run(); p.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    /// Самое опасное место — пути с пробелами и кавычками: проверяем реальным sh, а не глазами.
    func testShRoundTripsNastyStrings() {
        for s in ["plain", "with space", "it's", "a\"b", "$HOME `x` \\ ; &&", "/Users/Иван Петров/Fork.app/x y.sh"] {
            XCTAssertEqual(run("printf %s \(ShellQuote.sh(s))"), s)
        }
    }

    /// Прогоняем настоящий osascript без админ-прав: строка должна дойти до sh неизменной.
    func testAppleScriptLiteralSurvivesOsascript() throws {
        let nasty = #"a "quoted" \ back 'single' Fork Иван"#
        let script = "do shell script \"\(ShellQuote.appleScript("printf %s " + ShellQuote.sh(nasty)))\""
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript"); p.arguments = ["-e", script]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        try p.run(); p.waitUntilExit()
        XCTAssertEqual(String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                        .trimmingCharacters(in: .newlines), nasty)
    }

    func testAdminScriptShape() {
        XCTAssertEqual(ShellQuote.adminScript("echo hi"), #"do shell script "echo hi" with administrator privileges"#)
    }
}
