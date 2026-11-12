import SwiftUI
import ForkCore

extension Target {
    var title: String {
        switch self { case .xray: "Xray"; case .direct: "Напрямую"; case .block: "Блок" }
    }
}
extension RuleKind {
    var title: String {
        switch self {
        case .domain: "Домен точно"; case .domainSuffix: "Домен и поддомены"; case .domainKeyword: "Домен содержит"
        case .ipCidr: "Подсеть (CIDR)"; case .processName: "Процесс"; case .port: "Порт"
        }
    }
}

struct MenuView: View {
    @EnvironmentObject var m: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            row("Xray", binding: $m.settings.xrayOn,
                status: !m.settings.xrayOn ? .off : (m.xrayMissing ? .failed("нет профиля") : m.coreStatus),
                hint: m.settings.xrayOn ? (m.xray.map { "Сервер: \($0.name)" } ?? "Всё, кроме ваших правил") : nil)
            if !m.profiles.items.isEmpty {
                Menu {
                    ForEach(m.profiles.items) { profile in
                        Button {
                            m.select(profile.id)
                        } label: {
                            if m.xray?.id == profile.id {
                                Label(profile.name, systemImage: "checkmark")
                            } else {
                                Text(profile.name)
                            }
                        }
                    }
                } label: {
                    HStack {
                        Text("Профиль")
                        Spacer()
                        Text(m.xray?.name ?? "Выбрать").foregroundStyle(.secondary).lineLimit(1)
                        Image(systemName: "chevron.up.chevron.down").font(.caption2).foregroundStyle(.secondary)
                    }
                    .contentShape(Rectangle())
                }
            }
            if let n = m.notice {
                Text(n).font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            Button("Правила и профиль…") {
                NSApp.setActivationPolicy(.regular)
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            Button("Выход") { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
        }
        .padding(14).frame(width: 290)
    }

    func row(_ title: String, binding: Binding<Bool>, status: Status, hint: String?) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(status.text).font(.caption).foregroundStyle(color(status))
                if let h = hint { Text(h).font(.caption2).foregroundStyle(.secondary) }
            }
            Spacer()
            Toggle("", isOn: binding).labelsHidden().toggleStyle(.switch)
        }
    }

    func color(_ s: Status) -> Color {
        switch s { case .on: .green; case .failed: .red; case .starting: .orange; case .off: .secondary }
    }
}

struct RulesView: View {
    @EnvironmentObject var m: AppModel
    @State private var showLog = false

    /// «Хваталка»: пустое место строки для перетаскивания (поля ввода и списки драг перехватывают).
    private var grip: some View {
        Image(systemName: "line.3.horizontal").foregroundStyle(.secondary).frame(width: 22, height: 22)
            .contentShape(Rectangle()).help("Потяните, чтобы изменить порядок")
    }

    var body: some View {
        Form {
            Section {
                List {
                    ForEach($m.settings.rules) { $r in
                        HStack {
                            grip
                            Toggle("", isOn: $r.enabled).labelsHidden()
                            Picker("", selection: $r.kind) { ForEach(RuleKind.allCases, id: \.self) { Text($0.title).tag($0) } }
                                .labelsHidden().frame(width: 170)
                            TextField("значение", text: $r.value).textFieldStyle(.roundedBorder)
                            Picker("", selection: $r.target) { ForEach(Target.allCases, id: \.self) { Text($0.title).tag($0) } }
                                .labelsHidden().frame(width: 120)
                            Button { m.settings.rules.removeAll { $0.id == r.id } } label: { Image(systemName: "trash") }
                                .buttonStyle(.borderless)
                        }
                    }
                    .onMove { m.settings.rules.move(fromOffsets: $0, toOffset: $1) }
                }
                .frame(minHeight: 230)
                HStack {
                    Button("Добавить правило") { m.settings.rules.append(Rule(kind: .domainSuffix, value: "", target: .xray)) }
                    Spacer()
                    Text("Правила применяются сверху вниз; перетащите строки, чтобы изменить порядок.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } header: { Text("Ваши правила").font(.headline) }

            Section {
                Label(m.settings.xrayOn ? "Всё остальное → Xray" : "Всё остальное → напрямую (Xray выключен)", systemImage: "arrow.right")
                Text("Правила с выходом Xray пропускаются, когда Xray выключен.").font(.caption).foregroundStyle(.secondary)
            } header: { Text("Остальное").font(.headline) }


            Section {
                DisclosureGroup("Журнал", isExpanded: $showLog) {
                    ScrollView { Text(m.logText).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 160)
                    Button("Обновить") { m.refreshLog() }
                }
            }
        }
        .formStyle(.grouped)
        .onChange(of: showLog) { if $1 { m.refreshLog() } }
    }
}


// MARK: соединения (как в Clash Verge)

func formatBytes(_ n: Int64) -> String { ByteCountFormatter.string(fromByteCount: n, countStyle: .binary) }
func formatSpeed(_ n: Int64) -> String { n == 0 ? "0 Б/с" : "\(formatBytes(n))/с" }
func formatAge(_ d: Date?) -> String {
    guard let d else { return "" }
    let s = max(Int(Date().timeIntervalSince(d)), 0)
    return s < 60 ? "\(s) с" : s < 3600 ? "\(s / 60) мин" : "\(s / 3600) ч \(s % 3600 / 60) мин"
}

struct ConnectionsView: View {
    @EnvironmentObject var m: AppModel
    @State private var query = ""
    @State private var showService = false
    @State private var sortOrder = [KeyPathComparator(\ConnectionRow.startedAt, order: .reverse)]
    @State private var selectedConnection: String?
    @State private var ruleNotice: String?

    var filtered: [ConnectionRow] {
        let q = query.lowercased()
        return m.rows.filter { row in
            (showService || !row.isService) &&
            (q.isEmpty || [row.host, row.process, row.outbound, row.rule].contains { $0.lowercased().contains(q) })
        }.sorted(using: sortOrder)
    }

    var body: some View {
        VStack(spacing: 8) {
            HStack(spacing: 18) {
                Label(formatSpeed(m.speeds.down), systemImage: "arrow.down")
                Label(formatSpeed(m.speeds.up), systemImage: "arrow.up")
                Text("Всего: ↓ \(formatBytes(m.totals.down))  ↑ \(formatBytes(m.totals.up))").foregroundStyle(.secondary)
                Spacer()
                Text("Соединений: \(filtered.count)").foregroundStyle(.secondary)
                Button("Закрыть все") { m.closeConnection(nil) }.disabled(m.rows.isEmpty)
            }
            .font(.callout.monospacedDigit())
            HStack {
                TextField("Поиск по узлу, процессу, выходу, правилу", text: $query).textFieldStyle(.roundedBorder)
                Toggle("Служебные (\(m.rows.filter(\.isService).count))", isOn: $showService)
                    .help("Соединения Xray к серверу дублируют трафик приложений на уровне транспорта.")
            }
            if let ruleNotice { Text(ruleNotice).font(.caption).foregroundStyle(.secondary) }
            if m.coreStatus != .on {
                ContentUnavailableView("Нет соединений", systemImage: "arrow.triangle.branch",
                    description: Text("Включите Xray — соединения появятся здесь."))
            } else {
                Table(filtered, selection: $selectedConnection, sortOrder: $sortOrder) {
                    TableColumn("Узел", value: \.host) { Text($0.host).lineLimit(1) }.width(min: 160, ideal: 220)
                    TableColumn("Процесс", value: \.process) { Text($0.process).lineLimit(1) }.width(min: 70, ideal: 110)
                    TableColumn("Выход", value: \.outbound) { Text($0.outbound.isEmpty ? "—" : $0.outbound).foregroundStyle(color($0.outbound)) }.width(min: 60, ideal: 80)
                    TableColumn("Правило", value: \.rule) { Text($0.rule).lineLimit(1).foregroundStyle(.secondary) }.width(min: 90, ideal: 170)
                    TableColumn("↓", value: \.downSpeed) { Text(formatSpeed($0.downSpeed)).monospacedDigit() }.width(min: 70, ideal: 80)
                    TableColumn("↑", value: \.upSpeed) { Text(formatSpeed($0.upSpeed)).monospacedDigit() }.width(min: 70, ideal: 80)
                    TableColumn("Объём", value: \.totalBytes) { Text(formatBytes($0.totalBytes)).monospacedDigit() }.width(min: 70, ideal: 80)
                    TableColumn("Время", value: \.startedAt) { Text(formatAge($0.start)).monospacedDigit() }.width(min: 60, ideal: 70)
                    TableColumn("") { r in
                        Button { m.closeConnection(r.id) } label: { Image(systemName: "xmark.circle") }.buttonStyle(.borderless)
                    }.width(24)
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let id = ids.first, let connection = filtered.first(where: { $0.id == id }) {
                        if connection.domain != nil {
                            Menu("Создать правило по домену") {
                                ForEach(Target.allCases, id: \.self) { target in
                                    Button(target.title) { createRule(from: connection, kind: .domain, target: target) }
                                }
                            }
                        } else {
                            Menu("Создать правило по IP") {
                                ForEach(Target.allCases, id: \.self) { target in
                                    Button(target.title) { createRule(from: connection, kind: .ipCidr, target: target) }
                                }
                            }
                            .disabled(connection.ipCIDR == nil)
                        }
                        Menu("Создать правило по процессу") {
                            ForEach(Target.allCases, id: \.self) { target in
                                Button(target.title) { createRule(from: connection, kind: .processName, target: target) }
                            }
                        }
                        .disabled(connection.process.isEmpty)
                    }
                }
            }
        }
        .padding()
        .task(id: m.coreStatus) {
            while !Task.isCancelled { await m.pollConnections(); try? await Task.sleep(nanoseconds: 1_000_000_000) }
        }
    }

    func color(_ outbound: String) -> Color {
        switch outbound { case "xray": .blue; case "direct": .secondary; default: .primary }
    }

    func createRule(from connection: ConnectionRow, kind: RuleKind, target: Target) {
        m.createRule(from: connection, kind: kind, target: target)
        let value: String
        switch kind {
        case .domain: value = connection.domain ?? ""
        case .ipCidr: value = connection.ipCIDR ?? ""
        default: value = connection.process
        }
        ruleNotice = "Правило: \(value) → \(target.title). Изменить его можно во вкладке «Правила»."
    }
}


// MARK: серверы Xray

struct ServersView: View {
    @EnvironmentObject var m: AppModel
    @State private var link = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Button { Task { await m.runPings() } } label: { Label("Пинг всех", systemImage: "bolt.horizontal") }
                    .disabled(m.profiles.items.isEmpty || m.pingBlocked)
                Toggle("При включении Xray выбирать самый быстрый", isOn: $m.settings.autoBest)
                Spacer()
                Button("Из буфера обмена") { if let s = NSPasteboard.general.string(forType: .string) { Task { await m.importInput(s) } } }
                Button("Из Clash Verge") { Task { await m.importFromClashVerge() } }
            }
            HStack {
                TextField("Ссылка подписки https://, vless:// или YAML Clash", text: $link).textFieldStyle(.roundedBorder)
                Button("Добавить") { let value = link; link = ""; Task { await m.importInput(value) } }.disabled(link.isEmpty || m.subscriptionLoading)
            }
            if !m.profiles.subscriptions.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Подписки").foregroundStyle(.secondary)
                        Button("Обновить все") { Task { await m.refreshSubscriptions() } }.disabled(m.subscriptionLoading)
                        if m.subscriptionLoading { ProgressView().controlSize(.small) }
                    }
                    ForEach(m.profiles.subscriptions, id: \.self) { url in
                        HStack {
                            Text(URL(string: url).map { "\($0.host ?? "")/\($0.pathComponents.dropFirst().first ?? "")" } ?? "Подписка")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Обновить") { Task { await m.refreshSubscription(url) } }.disabled(m.subscriptionLoading)
                            Button { m.removeSubscription(url) } label: { Image(systemName: "trash") }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            }
            if let n = m.notice { Text(n).font(.callout).foregroundStyle(.orange) }
            if m.pingBlocked {
                Text("Пока Xray включён, пинг недоступен: проверка шла бы через собственный туннель.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Пинг — время TCP-соединения с сервером (достижимость и задержка), не скорость через прокси.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if m.profiles.items.isEmpty {
                ContentUnavailableView("Серверов нет", systemImage: "server.rack",
                    description: Text("Вставьте ссылку подписки или vless:// либо загрузите профили из Clash Verge."))
            } else {
                List {
                    ForEach(m.profiles.items) { p in
                        HStack(spacing: 10) {
                            Button { m.select(p.id) } label: {
                                Image(systemName: m.profiles.active?.id == p.id ? "largecircle.fill.circle" : "circle")
                            }.buttonStyle(.borderless)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(p.name).font(.body)
                                    Text(p.kind).font(.caption2).padding(.horizontal, 5).padding(.vertical, 1)
                                        .background(.quaternary, in: Capsule())
                                }
                                Text("\(p.server):\(p.port) · \(p.serverName)").font(.caption).foregroundStyle(.secondary)
                                if let source = p.sourceURL { Text("Подписка: \(URL(string: source)?.host ?? "")").font(.caption2).foregroundStyle(.tertiary) }
                            }
                            Spacer()
                            pingLabel(m.pings[p.id])
                            Button { m.remove(p.id) } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                        }
                        .contentShape(Rectangle()).onTapGesture { m.select(p.id) }
                    }
                }
            }
        }
        .padding()
    }

    @ViewBuilder func pingLabel(_ s: PingState?) -> some View {
        switch s {
        case nil: Text("—").foregroundStyle(.secondary)
        case .testing?: ProgressView().controlSize(.small)
        case .result(let r)?:
            switch r {
            case .ok(let ms): Text("\(ms) мс").monospacedDigit().foregroundStyle(ms < 150 ? Color.green : ms < 400 ? .orange : .red)
            case .failed(let why): Text(why).foregroundStyle(.red)
            }
        }
    }
}
