import Foundation

public enum SubscriptionImport {
    public static func validatedURL(_ text: String) throws -> URL {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: value), url.scheme?.lowercased() == "https", url.host != nil,
              url.user == nil, url.password == nil else {
            throw ForkError.importFailed("Нужна ссылка подписки https://")
        }
        return url
    }

    /// Verge Rev stores remote profile URLs in profiles.yaml; other item types are local patches.
    public static func vergeRemoteURLs(_ yaml: String) -> [String] {
        var urls: [String] = []
        var isRemote = false
        var candidate: String?
        func flush() {
            if isRemote, let candidate, !urls.contains(candidate),
               (try? validatedURL(candidate)) != nil { urls.append(candidate) }
        }
        for line in yaml.split(whereSeparator: \.isNewline).map(String.init) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("- uid:") { flush(); isRemote = false; candidate = nil }
            else if trimmed == "type: remote" { isRemote = true }
            else if trimmed.hasPrefix("url:") {
                candidate = String(trimmed.dropFirst(4)).trimmingCharacters(in: CharacterSet(charactersIn: " \"'"))
            }
        }
        flush()
        return urls
    }
}
