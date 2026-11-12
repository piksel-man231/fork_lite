import Foundation

/// Экранирование для команды, которую мы передаём в `osascript ... do shell script ... with administrator privileges`.
public enum ShellQuote {
    /// Строка для sh: в одинарных кавычках, внутренние ' → '\''.
    public static func sh(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// Содержимое строкового литерала AppleScript: экранируем \ и ".
    public static func appleScript(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// Готовый аргумент `-e` для osascript.
    public static func adminScript(_ shellCommand: String) -> String {
        "do shell script \"\(appleScript(shellCommand))\" with administrator privileges"
    }
}
