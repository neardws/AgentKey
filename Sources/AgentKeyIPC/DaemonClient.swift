import Foundation
import AgentKeyCore

/// Thin client used by `agentkey` and `agentkey-mcp`. Holds no keys.
public final class DaemonClient: @unchecked Sendable {
    let conn: UnixConnection
    var nextID = 1
    public var onProgress: (([String: String]) -> Void)?

    public init(socketPath: String = AKPaths.socket.path) throws {
        do { conn = try UnixClient.connect(path: socketPath) }
        catch { throw RPCError(.locked, "agentkeyd not reachable at \(socketPath): \(error). Start it with `launchctl kickstart gui/$(id -u)/com.neardws.agentkey.agentkeyd` or run `agentkeyd`.") }
    }

    public func call(_ method: String, _ params: [String: String] = [:]) throws -> [String: String] {
        let id = nextID; nextID += 1
        try conn.send(RPCRequest(id: id, method: method, params: params))
        while true {
            let msg = try JSONDecoder().decode(RPCMessage.self, from: try conn.readFrame())
            if msg.method == "progress" { onProgress?(msg.params ?? [:]); continue }
            guard msg.id == id else { continue }
            if let e = msg.error { throw e }
            return msg.result ?? [:]
        }
    }
}
