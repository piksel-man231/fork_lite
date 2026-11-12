import Foundation
import Network

public enum PingResult: Equatable, Sendable {
    case ok(Int)            // миллисекунды до установления TCP-соединения
    case failed(String)
}

/// Время TCP-рукопожатия до сервера (включая DNS). Это достижимость и RTT, а не скорость через прокси.
/// Флаг трогают только колбэки одной serial-очереди.
final class Flag: @unchecked Sendable { var done = false }

public enum TCPPing {
    public static func measure(host: String, port: Int, timeout: TimeInterval = 3) async -> PingResult {
        guard let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)), port > 0, port < 65536 else { return .failed("неверный порт") }
        return await withCheckedContinuation { cont in
            let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
            let q = DispatchQueue(label: "fork.ping")          // все колбэки на одной очереди → done без блокировок
            let flag = Flag()
            let t0 = DispatchTime.now()
            func finish(_ r: PingResult) {
                guard !flag.done else { return }
                flag.done = true; conn.cancel(); cont.resume(returning: r)
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    finish(.ok(Int(Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)))
                case .failed: finish(.failed("недоступен"))
                case .waiting(let e):
                    if case .posix(let c) = e, c == .ECONNREFUSED { finish(.failed("отказ")) }   // остальное — ждём до тайм-аута
                default: break
                }
            }
            q.asyncAfter(deadline: .now() + timeout) { finish(.failed("тайм-аут")) }
            conn.start(queue: q)
        }
    }
}
