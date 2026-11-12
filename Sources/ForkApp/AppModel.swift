import Foundation
import AppKit
import ForkCore

enum PingState: Equatable {
    case testing
    case result(PingResult)
}

enum Status: Equatable {
    case off, starting, on, failed(String)
    var text: String {
        switch self {
        case .off: return "выключен"
        case .starting: return "подключается…"
        case .on: return "работает"
        case .failed(let m): return m
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    static let helperDir = "/usr/local/fork_lite"
    static let coreLog = "/usr/local/fork_lite/run/core.log"

    @Published var settings: Settings { didSet { if settings != oldValue { settingsChanged(oldValue) } } }
    @Published var profiles = Profiles()
    @Published var subscriptionLoading = false
    @Published var pings: [UUID: PingState] = [:]
    var xray: XrayProfile? { profiles.active }
    /// Пинговать надо ДО того, как TUN начнёт перехватывать трафик самого Fork; поэтому выбор — только при включении.
    private var pendingAutoPick = false
    var pingBlocked: Bool { settings.xrayOn && coreStatus != .off }
    @Published var coreStatus: Status = .off
    @Published var notice: String?
    @Published var logText = ""

    static let apiPort = 19091
    private let apiSecret = UUID().uuidString   // новый на каждый запуск приложения
    private var api: ClashAPI { ClashAPI(port: Self.apiPort, secret: apiSecret) }
    private var tracker = ConnectionTracker()
    @Published var rows: [ConnectionRow] = []
    @Published var speeds = (up: Int64(0), down: Int64(0))
    @Published var totals = (up: Int64(0), down: Int64(0))

    private var applyTask: Task<Void, Never>?
    private var applying = false, again = false
    private var coreProc: Process?
    private var awgProfile: XrayProfile?
    private var awgIface: String?
    private var awgMonitorTask: Task<Void, Never>?

    /// Скрипты помощника в приложении совпадают с установленными (без бандла — считаем актуальными, это запуск из исходников).
    var helperUpToDate: Bool {
        guard let dir = Bundle.main.resourcePath.map({ $0 + "/helper" }),
              let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return true }
        let scriptsMatch = names.allSatisfy {
            FileManager.default.contentsEqual(atPath: "\(dir)/\($0)", andPath: "\(Self.helperDir)/\($0)")
        }
        let binariesMatch = ["sing-box", "amneziawg-go", "awg"].allSatisfy { name in
            guard let bundled = Bundle.main.resourcePath.map({ "\($0)/vendor/bin/\(name)" }) else { return false }
            return FileManager.default.contentsEqual(atPath: bundled, andPath: "\(Self.helperDir)/\(name)")
        }
        return scriptsMatch && binariesMatch
    }

    var helperInstalled: Bool { FileManager.default.isExecutableFile(atPath: "\(Self.helperDir)/fork-core-start") }
    var xrayMissing: Bool { settings.xrayOn && xray == nil }

    init() {
        var s = Store.load("settings.json", as: Settings.self) ?? Settings()
        // Переключатели сознательно не переживают перезапуск: приложение не должно само перехватывать сеть при входе в систему.
        s.xrayOn = false
        settings = s
        if let ps = Store.load("profiles.json", as: Profiles.self) { profiles = ps }
        else if let one = Store.load("xray.json", as: XrayProfile.self) {   // перенос из версии с одним профилем
            profiles.add([one]); Store.save(profiles, name: "profiles.json")
        }
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: nil) { _ in
            _ = Shell.sudo("fork-core-stop"); _ = Shell.sudo("fork-awg-stop"); XraySidecar.shared.stop()
        }
        if !profiles.subscriptions.isEmpty { Task { await refreshSubscriptions() } }
    }

    // MARK: настройки

    private func settingsChanged(_ old: Settings) {
        Store.save(settings, name: "settings.json")
        if (settings.xrayOn) && (!helperInstalled || !helperUpToDate) {
            let update = helperInstalled
            settings.xrayOn = false
            notice = update ? "Помощник устарел — нужно обновить." : "Не установлен помощник — без него нельзя перехватывать трафик."
            DispatchQueue.main.async { self.promptInstallHelper(update: update) }   // окно, а не строка в меню, которая пропадает вместе с ним
            return
        }
        notice = nil
        let running = coreStatus == .on || coreStatus == .starting
        if !old.xrayOn && settings.xrayOn { pendingAutoPick = true }
        let toggled = old.xrayOn != settings.xrayOn
        // Правка правил нужна ядру только если оно уже работает; переключатели — всегда.
        guard toggled || running else { return }
        applyTask?.cancel()
        applyTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: toggled ? 150_000_000 : 1_200_000_000)
            if Task.isCancelled { return }
            await self?.apply()
        }
    }

    func apply() async {
        if applying { again = true; return }
        applying = true; defer { applying = false }
        repeat {
            again = false
            await applyOnce()
        } while again
    }

    private func applyOnce() async {
        // 1.5. Xray только что включили: самый быстрый сервер (пока TUN не поднят, пинг идёт по обычной сети).
        if pendingAutoPick {
            pendingAutoPick = false
            if settings.xrayOn, settings.autoBest, xray?.supportsTCPPing == true, profiles.items.count > 1 { await pickFastest() }
        }

        if let selected = xray, settings.xrayOn, selected.protocolType == "amneziawg" {
            if awgProfile != selected, !(await startAwg(selected)) {
                settings.xrayOn = false
            }
        } else if awgProfile != nil {
            await stopAwg()
        }

        // 1.6. Для xhttp поднимаем локальный xray (SOCKS) до ядра; для остальных транспортов он не нужен.
        if let x = xray, settings.xrayOn, x.needsSidecar {
            if !(await startSidecar(x)) {
                settings.xrayOn = false          // didSet стирает notice, поэтому текст ставит startSidecar уже после
                notice = sidecarError
            }
        } else { XraySidecar.shared.stop() }

        // 2. Ядро маршрутизации: перегенерируем конфиг под текущее состояние.
        let b = ConfigBuilder(settings: settings, xray: xray, clashPort: Self.apiPort,
                              clashSecret: apiSecret, awgInterface: awgIface)
        if settings.xrayOn && xray == nil { notice = "Подключение включено, но профиль не загружен. Откройте «Серверы»." }
        guard b.needsCore else { await stopCore(); return }
        do { try Store.writeConfig(b.json()) } catch { coreStatus = .failed("не записал конфиг: \(error.localizedDescription)"); return }
        await startCore()
    }

    // MARK: ядро

    private func startAwg(_ profile: XrayProfile) async -> Bool {
        if awgProfile != nil { await stopAwg() }
        do {
            try AwgConfigBuilder.config(profile).write(to: Store.awgConfigURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Store.awgConfigURL.path)
        } catch {
            notice = "Не записал AmneziaWG-конфигурацию: \(error.localizedDescription)"
            return false
        }
        let result = await Task.detached { Shell.sudo("fork-awg-start") }.value
        guard result.code == 0, let iface = result.out.split(whereSeparator: \.isNewline).last.map(String.init),
              iface.hasPrefix("utun") else {
            notice = "AmneziaWG не запустился: \(result.out.trimmingCharacters(in: .whitespacesAndNewlines).suffix(300))"
            return false
        }
        awgIface = iface; awgProfile = profile
        awgMonitorTask = Task { await monitorAwg() }
        return true
    }

    private func stopAwg() async {
        awgMonitorTask?.cancel(); awgMonitorTask = nil
        awgProfile = nil; awgIface = nil
        await Task.detached { _ = Shell.sudo("fork-awg-stop") }.value
    }

    private func monitorAwg() async {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if Task.isCancelled || awgProfile == nil { return }
            let alive = await Task.detached {
                Shell.run("/usr/bin/pgrep", ["-f", "/usr/local/fork_lite/amneziawg-go"]).code == 0
            }.value
            if !alive {
                settings.xrayOn = false
                notice = "AmneziaWG остановился. Проверьте конфигурацию и журнал."
                return
            }
        }
    }

    private func startCore() async {
        coreStatus = .starting
        coreProc?.terminate(); coreProc = nil
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", "\(Self.helperDir)/fork-core-start"]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        p.terminationHandler = { [weak self] proc in
            Task { @MainActor in
                guard let self, self.coreProc === proc else { return }
                self.coreStatus = .failed("ядро остановилось (код \(proc.terminationStatus))")
            }
        }
        do { try p.run() } catch { coreStatus = .failed("не запустилось: \(error.localizedDescription)"); return }
        coreProc = p
        for _ in 0..<15 {
            try? await Task.sleep(nanoseconds: 400_000_000)
            if !p.isRunning { return }  // terminationHandler уже выставил ошибку
            if Shell.tail(Self.coreLog).contains("sing-box started") { coreStatus = .on; return }
        }
        coreStatus = .failed("ядро не отозвалось, см. журнал")
    }

    private func stopCore() async {
        XraySidecar.shared.stop()
        let old = coreProc; coreProc = nil
        await Task.detached { _ = Shell.sudo("fork-core-stop") }.value
        old?.terminate()
        coreStatus = .off
    }

    // MARK: установка помощника

    /// Окно с предложением установить помощника (один раз, спросит пароль администратора).
    func promptInstallHelper(update: Bool = false) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = update ? "Помощник устарел" : "Не установлен помощник"
        a.informativeText = update
            ? "В этой версии приложения помощник изменился. Обновление спросит пароль Mac."
            : "Чтобы перехватывать трафик, нужны права администратора. Установка делается один раз и спросит пароль Mac."
        a.addButton(withTitle: update ? "Обновить" : "Установить"); a.addButton(withTitle: "Отмена")
        if a.runModal() == .alertFirstButtonReturn { installHelper() }
    }

    func installHelper() {
        guard let script = Bundle.main.path(forResource: "install-helper", ofType: "sh") else {
            notice = "В приложении нет установщика — соберите его через scripts/build-app.sh"; return
        }
        guard Bundle.main.resourcePath.map({ FileManager.default.isExecutableFile(atPath: $0 + "/vendor/bin/sing-box") }) == true else {
            notice = "В приложении нет sing-box. Пересоберите Fork Lite."; return
        }
        notice = "Устанавливаю помощника…"
        let cmd = "SUDO_USER=\(ShellQuote.sh(NSUserName())) /bin/bash \(ShellQuote.sh(script))"
        Task {
            let r = await Task.detached { Shell.run("/usr/bin/osascript", ["-e", ShellQuote.adminScript(cmd)]) }.value
            if r.code == 0 { notice = "Помощник установлен. Включайте подключение." }
            else if r.out.contains("User canceled") || r.out.contains("-128") { notice = "Установка отменена." }
            else { notice = "Не удалось установить помощника: \(r.out.trimmingCharacters(in: .whitespacesAndNewlines).suffix(300))" }
        }
    }

    // MARK: профили Xray

    func importProfiles(_ text: String) {
        do {
            let added = profiles.add(try ProfileImport.parseMany(text))
            Store.save(profiles, name: "profiles.json")
            notice = added == 0 ? "Эти серверы уже в списке" : nil
        } catch { notice = error.localizedDescription }
    }

    func importInput(_ text: String) async {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("http://") || value.lowercased().hasPrefix("https://") {
            await refreshSubscription(value)
        } else {
            importProfiles(value)
        }
    }

    func refreshSubscription(_ value: String) async {
        guard !subscriptionLoading else { return }
        subscriptionLoading = true
        defer { subscriptionLoading = false }
        do {
            let url = try SubscriptionImport.validatedURL(value)
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 15
            config.timeoutIntervalForResource = 30
            let (data, response) = try await URLSession(configuration: config).data(from: url)
            guard response.url?.scheme?.lowercased() == "https" else {
                throw ForkError.importFailed("Подписка перенаправила на небезопасный адрес")
            }
            guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                throw ForkError.importFailed("Сервер подписки вернул ошибку HTTP")
            }
            guard data.count <= 2_000_000, let text = String(data: data, encoding: .utf8) else {
                throw ForkError.importFailed("Ответ подписки слишком большой или не в UTF-8")
            }
            let incoming = try ProfileImport.parseMany(text)
            let old = profiles.active
            profiles.sync(url.absoluteString, profiles: incoming)
            Store.save(profiles, name: "profiles.json")
            if settings.xrayOn && old != profiles.active { settingsChangedForce() }
            notice = "Подписка обновлена: \(incoming.count) сервер(ов)"
        } catch {
            let reason = error is URLError ? "ошибка сети или сертификата" : error.localizedDescription
            notice = "Не удалось обновить подписку: \(reason)"
        }
    }

    func refreshSubscriptions() async {
        for url in profiles.subscriptions { await refreshSubscription(url) }
    }

    func removeSubscription(_ url: String) {
        let old = profiles.active
        profiles.subscriptions.removeAll { $0 == url }
        profiles.items.removeAll { $0.sourceURL == url }
        if !profiles.items.contains(where: { $0.id == profiles.selected }) { profiles.selected = profiles.items.first?.id }
        Store.save(profiles, name: "profiles.json")
        if settings.xrayOn && old != profiles.active { settingsChangedForce() }
    }

    func importFromClashVerge() async {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles")
        let registry = dir.deletingLastPathComponent().appendingPathComponent("profiles.yaml")
        let remoteURLs = (try? String(contentsOf: registry, encoding: .utf8))
            .map(SubscriptionImport.vergeRemoteURLs) ?? []
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        var found: [XrayProfile] = []
        for f in files where f.pathExtension == "yaml" {
            if let t = try? String(contentsOf: f, encoding: .utf8), let ps = try? ProfileImport.parseMany(t) { found += ps }
        }
        for url in remoteURLs { await refreshSubscription(url) }
        let added = profiles.add(found)
        Store.save(profiles, name: "profiles.json")
        if found.isEmpty && remoteURLs.isEmpty { notice = "В Clash Verge не нашёл поддерживаемых профилей" }
        else if remoteURLs.isEmpty { notice = added == 0 ? "Все серверы из Clash Verge уже в списке" : "Импортировано из Clash Verge: \(added)" }
    }

    func select(_ id: UUID) {
        guard profiles.items.contains(where: { $0.id == id }), profiles.selected != id else { return }
        profiles.selected = id; Store.save(profiles, name: "profiles.json")
        // A manual choice should remain selected on the next Xray activation.
        settings.autoBest = false
        if settings.xrayOn { settingsChangedForce() }   // перезапуск ядра на новый сервер
    }

    func createRule(from connection: ConnectionRow, kind: RuleKind, target: Target) {
        let value: String
        switch kind {
        case .domain: guard let domain = connection.domain else { return }; value = domain
        case .ipCidr: guard let ipCIDR = connection.ipCIDR else { return }; value = ipCIDR
        case .processName: guard !connection.process.isEmpty else { return }; value = connection.process
        default: return
        }
        var rules = settings.rules
        if let index = rules.firstIndex(where: { $0.kind == kind && $0.value == value && $0.target == target }) {
            var existing = rules.remove(at: index)
            existing.enabled = true
            rules.insert(existing, at: 0)
        } else {
            rules.insert(Rule(kind: kind, value: value, target: target), at: 0)
        }
        settings.rules = rules
    }

    func remove(_ id: UUID) {
        let wasActive = profiles.active?.id == id
        profiles.remove(id); pings[id] = nil
        Store.save(profiles, name: "profiles.json")
        if wasActive && settings.xrayOn { settingsChangedForce() }
    }

    // MARK: пинг

    /// Пингует все серверы параллельно, результаты появляются в списке по мере прихода.
    @discardableResult
    func runPings() async -> [UUID: PingResult] {
        let items = profiles.items
        for p in items { pings[p.id] = p.supportsTCPPing ? .testing : .result(.failed("UDP: нет TCP-пинга")) }
        var results: [UUID: PingResult] = [:]
        await withTaskGroup(of: (UUID, PingResult).self) { g in
            for p in items where p.supportsTCPPing { g.addTask { (p.id, await TCPPing.measure(host: p.server, port: p.port)) } }
            for await (id, r) in g { results[id] = r; pings[id] = .result(r) }
        }
        return results
    }

    private var sidecarError = ""

    private func startSidecar(_ x: XrayProfile) async -> Bool {
        do { try XraySidecar.shared.start(x) } catch { sidecarError = error.localizedDescription; return false }
        for _ in 0..<20 {
            if case .ok = await TCPPing.measure(host: "127.0.0.1", port: ConfigBuilder.sidecarPort, timeout: 0.5) { return true }
            if !XraySidecar.shared.isRunning { break }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        XraySidecar.shared.stop()
        sidecarError = "Сопроцесс xray не запустился (проверьте профиль xhttp)"
        return false
    }

    private func pickFastest() async {
        coreStatus = .starting
        notice = "Проверяю серверы…"
        let results = await runPings()
        if let best = profiles.fastest(results) {
            profiles.selected = best.id; Store.save(profiles, name: "profiles.json")
            if case .ok(let ms)? = results[best.id] { notice = "Выбран самый быстрый: \(best.name) — \(ms) мс" }
        } else {
            notice = "Ни один сервер не ответил на пинг. Оставил выбранный, пробую подключиться."
        }
    }

    private func settingsChangedForce() { applyTask?.cancel(); applyTask = Task { await apply() } }

    // MARK: соединения

    func pollConnections() async {
        guard coreStatus == .on else {
            if !rows.isEmpty { rows = []; tracker = ConnectionTracker() }
            return
        }
        guard let snap = try? await api.connections() else { return }
        rows = tracker.update(snap)
        speeds = (tracker.upSpeed, tracker.downSpeed); totals = (tracker.uploadTotal, tracker.downloadTotal)
    }

    func closeConnection(_ id: String?) {
        Task { await api.close(id); await pollConnections() }
    }

    func refreshLog() {
        let core = Shell.tail(Self.coreLog, bytes: 4000)
        logText = core
    }
}
