import Foundation
import AgentKeyCore
import AgentKeyIPC

// agentkey-mcp — minimal MCP (Model Context Protocol) server over stdio.
// A thin client of agentkeyd: holds no keys; every secret use is approved on the Mac
// with Touch ID or Apple Watch. Plaintext is only returned by get_secret, which is
// refused unless the policy grants `reveal` to this agent AND the item.

setvbuf(stdout, nil, _IOLBF, 0)
let args = CommandLine.arguments
let agent = args.firstIndex(of: "--agent").flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil }
    ?? ProcessInfo.processInfo.environment["AGENTKEY_AGENT"] ?? "mcp"
let socketPath = args.firstIndex(of: "--socket").flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } ?? AKPaths.socket.path

final class DataBox: @unchecked Sendable { var data = Data() }

func log(_ s: String) { FileHandle.standardError.write(Data("[agentkey-mcp] \(s)\n".utf8)) }

func send(_ obj: [String: Any]) {
    guard let d = try? JSONSerialization.data(withJSONObject: obj, options: [.withoutEscapingSlashes]) else { return }
    FileHandle.standardOutput.write(d + Data([0x0a]))
}

func toolResult(_ text: String, structured: [String: Any]? = nil, isError: Bool = false) -> [String: Any] {
    var r: [String: Any] = ["content": [["type": "text", "text": text]], "isError": isError]
    if let structured { r["structuredContent"] = structured }
    return r
}

let tools: [[String: Any]] = [
    ["name": "list_items",
     "description": "List AgentKey vault items (titles, refs, field ids, allowed release modes). Never returns secret values.",
     "inputSchema": ["type": "object", "properties": ["query": ["type": "string", "description": "optional case-insensitive filter"]]]],
    ["name": "run_with_secret",
     "description": "Run a command with secrets injected as environment variables (preferred: you never see the plaintext). Requires the user's Touch ID / Apple Watch approval on the Mac. Output is redacted.",
     "inputSchema": ["type": "object", "required": ["command", "env"], "properties": [
        "command": ["type": "array", "items": ["type": "string"], "description": "argv, e.g. [\"curl\",\"-H\",\"Authorization: Bearer $TOKEN\",...] is NOT shell-expanded; use [\"sh\",\"-c\",\"...\"] only if needed"],
        "env": ["type": "object", "additionalProperties": ["type": "string"], "description": "map NAME -> ak://item[/field]"],
        "timeout_seconds": ["type": "integer", "default": 120]]]],
    ["name": "get_totp",
     "description": "Get the current one-time code for a TOTP item (approval-gated). Never returns the seed.",
     "inputSchema": ["type": "object", "required": ["ref"], "properties": ["ref": ["type": "string"]]]],
    ["name": "vault_health",
     "description": "Analyze vault hygiene (reused/weak/duplicate/stale/not-rotated/missing-TOTP/trash). Returns findings with item refs and metrics only — never secret values.",
     "inputSchema": ["type": "object", "properties": ["stale_days": ["type": "integer"], "rotation_days": ["type": "integer"]]]],
    ["name": "propose_cleanup",
     "description": "Create a cleanup PLAN for the user to review. Nothing changes until the user approves it on their Mac with Touch ID / Apple Watch (`agentkey plan apply`). Omit actions to derive a plan from vault_health. Action kinds: merge (needs keep), trash, archive, restore, flag_rotation, add_tags, remove_tags (need tags), purge (trashed items only). Use item ids from list_items / vault_health.",
     "inputSchema": ["type": "object", "properties": [
        "title": ["type": "string"],
        "actions": ["type": "array", "items": ["type": "object", "required": ["id", "kind", "itemIDs", "reason"], "properties": [
            "id": ["type": "string"], "kind": ["type": "string"], "itemIDs": ["type": "array", "items": ["type": "string"]],
            "keep": ["type": "string"], "tags": ["type": "array", "items": ["type": "string"]], "reason": ["type": "string"]]]]]]],
    ["name": "get_plan_status",
     "description": "Get a cleanup plan's status and per-action state (pending/applied/rejected). Omit plan_id to list plans. Agents cannot apply plans.",
     "inputSchema": ["type": "object", "properties": ["plan_id": ["type": "string"]]]],
    ["name": "get_secret",
     "description": "Return a secret's PLAINTEXT. Disabled by default; only works if the user enabled `reveal` for this agent and item. Approval-gated. Prefer run_with_secret.",
     "inputSchema": ["type": "object", "required": ["ref"], "properties": ["ref": ["type": "string", "description": "ak://item[/field]"]]]],
]

func withClient<T>(_ f: (DaemonClient) throws -> T) throws -> T {
    let c = try DaemonClient(socketPath: socketPath)
    c.onProgress = { p in log("awaiting approval on Mac, code [\(p["code"] ?? "?")] for \(p["ref"] ?? "")") }
    return try f(c)
}

func callTool(_ name: String, _ a: [String: Any]) -> [String: Any] {
    do {
        switch name {
        case "list_items":
            let r = try withClient { try $0.call("list", ["agent": agent]) }
            var items = (try? JSONDecoder().decode([ItemOverview].self, from: Data((r["items"] ?? "[]").utf8))) ?? []
            if let q = (a["query"] as? String)?.lowercased(), !q.isEmpty {
                items = items.filter { $0.title.lowercased().contains(q) || $0.tags.contains { $0.lowercased().contains(q) } }
            }
            let rows = items.map { ["id": $0.id.uuidString, "ref": $0.ref, "title": $0.title, "kind": $0.kind.rawValue,
                                    "fields": $0.fields.map(\.id), "modes": $0.agentModes.map(\.rawValue)] as [String: Any] }
            let text = items.isEmpty ? "No items." : items.map { "\($0.ref) (\($0.kind.rawValue)) fields=\($0.fields.map(\.id).joined(separator: ",")) modes=\($0.agentModes.map(\.rawValue).joined(separator: ","))" }.joined(separator: "\n")
            return toolResult(text, structured: ["items": rows])

        case "vault_health":
            var p = ["agent": agent]
            if let d = a["stale_days"] as? Int { p["staleDays"] = String(d) }
            if let d = a["rotation_days"] as? Int { p["rotationDays"] = String(d) }
            let r = try withClient { try $0.call("health", p) }
            let obj = (try? JSONSerialization.jsonObject(with: Data((r["report"] ?? "{}").utf8))) as? [String: Any] ?? [:]
            let rep = try? Vault.decoder.decode(HealthReport.self, from: Data((r["report"] ?? "{}").utf8))
            let text = rep.map { r in "score \(r.score)/100, \(r.findings.count) findings\n" + r.findings.map { "[\($0.severity.rawValue)] \($0.kind.rawValue): \($0.refs.joined(separator: ", ")) — \($0.detail) ids=\($0.itemIDs.map(\.uuidString).joined(separator: ","))" }.joined(separator: "\n") } ?? ""
            return toolResult(text, structured: obj)

        case "propose_cleanup":
            var p = ["agent": agent]
            if let t = a["title"] as? String { p["title"] = t }
            if let acts = a["actions"] {
                p["actions"] = String(decoding: try JSONSerialization.data(withJSONObject: acts), as: UTF8.self)
            }
            let r = try withClient { try $0.call("plan.create", p) }
            let obj = (try? JSONSerialization.jsonObject(with: Data((r["plan"] ?? "{}").utf8))) as? [String: Any] ?? [:]
            let id = obj["id"] as? String ?? "?"
            return toolResult("Created plan \(id) with \((obj["actions"] as? [Any])?.count ?? 0) action(s). Ask the user to review and approve it on their Mac: `agentkey plan show \(id)` then `agentkey plan apply \(id)` (Touch ID / Apple Watch). You cannot apply it.", structured: obj)

        case "get_plan_status":
            if let id = a["plan_id"] as? String {
                let r = try withClient { try $0.call("plan.show", ["id": id, "agent": agent]) }
                let obj = (try? JSONSerialization.jsonObject(with: Data((r["plan"] ?? "{}").utf8))) as? [String: Any] ?? [:]
                let acts = (obj["actions"] as? [[String: Any]] ?? []).map { "\($0["id"] ?? "") \($0["kind"] ?? "") → \($0["state"] ?? "")" }
                return toolResult("\(id): \(obj["status"] ?? "?")\n" + acts.joined(separator: "\n"), structured: obj)
            }
            let r = try withClient { try $0.call("plan.show", ["agent": agent]) }
            let arr = (try? JSONSerialization.jsonObject(with: Data((r["plans"] ?? "[]").utf8))) as? [[String: Any]] ?? []
            return toolResult(arr.map { "\($0["id"] ?? "") [\($0["status"] ?? "")] \($0["title"] ?? "")" }.joined(separator: "\n"), structured: ["plans": arr])

        case "get_totp":
            guard let ref = a["ref"] as? String else { return toolResult("ref required", isError: true) }
            let r = try withClient { try $0.call("totp", ["ref": ref, "agent": agent]) }
            return toolResult("\(r["code"] ?? "") (valid \(r["expiresIn"] ?? "?")s)", structured: ["code": r["code"] ?? "", "expires_in": Int(r["expiresIn"] ?? "") ?? 0])

        case "get_secret":
            guard let ref = a["ref"] as? String else { return toolResult("ref required", isError: true) }
            let r = try withClient { try $0.call("release", ["ref": ref, "mode": "reveal", "agent": agent]) }
            let v = r["value"].flatMap { Data(base64Encoded: $0) }.map { String(decoding: $0, as: UTF8.self) } ?? ""
            return toolResult(v, structured: ["ref": r["ref"] ?? ref, "value": v])

        case "run_with_secret":
            guard let cmd = a["command"] as? [String], !cmd.isEmpty, let envMap = a["env"] as? [String: String], !envMap.isEmpty
            else { return toolResult("command (array) and env (object) required", isError: true) }
            let timeout = (a["timeout_seconds"] as? Int) ?? 120
            var env = ProcessInfo.processInfo.environment
            var secrets: [(label: String, value: String)] = []
            try withClient { c in
                for (name, ref) in envMap.sorted(by: { $0.key < $1.key }) {
                    let r = try c.call("release", ["ref": ref, "mode": "run", "agent": agent, "command": cmd.joined(separator: " ")])
                    let v = r["value"].flatMap { Data(base64Encoded: $0) }.map { String(decoding: $0, as: UTF8.self) } ?? ""
                    env[name] = v; secrets.append((r["ref"] ?? ref, v))
                }
            }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            p.arguments = cmd; p.environment = env
            let out = Pipe(), err = Pipe()
            p.standardOutput = out; p.standardError = err
            p.standardInput = FileHandle.nullDevice
            try p.run()
            let deadline = Date().addingTimeInterval(TimeInterval(timeout))
            let outBox = DataBox(), errBox = DataBox()
            let g = DispatchGroup()
            g.enter(); DispatchQueue.global().async { outBox.data = out.fileHandleForReading.readDataToEndOfFile(); g.leave() }
            g.enter(); DispatchQueue.global().async { errBox.data = err.fileHandleForReading.readDataToEndOfFile(); g.leave() }
            while p.isRunning && Date() < deadline { usleep(50_000) }
            var timedOut = false
            if p.isRunning { p.terminate(); timedOut = true }
            p.waitUntilExit(); g.wait()
            let outData = outBox.data, errData = errBox.data
            let red = Redactor(secrets: secrets)
            let cap = 64 * 1024
            let so = red.redact(String(decoding: outData.prefix(cap), as: UTF8.self))
            let se = red.redact(String(decoding: errData.prefix(cap), as: UTF8.self))
            let status = Int(p.terminationStatus)
            let warn = red.warning.map { "⚠️ \($0)\n" } ?? ""
            let text = "\(warn)exit \(status)\(timedOut ? " (timed out)" : "")\n--- stdout ---\n\(so)\n--- stderr ---\n\(se)"
            return toolResult(text, structured: ["exit_code": status, "stdout": so, "stderr": se, "timed_out": timedOut,
                                                 "warnings": red.warning.map { [$0] } ?? [], "weak_secrets": red.weakSecrets],
                              isError: status != 0)

        default:
            return toolResult("unknown tool \(name)", isError: true)
        }
    } catch let e as RPCError {
        return toolResult("AgentKey: \(e.message)", structured: ["error_code": e.code], isError: true)
    } catch {
        return toolResult("AgentKey: \(error)", isError: true)
    }
}

log("starting (agent=\(agent))")
while let line = readLine(strippingNewline: true) {
    guard !line.isEmpty, let d = line.data(using: .utf8),
          let msg = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
    let id = msg["id"]
    let method = msg["method"] as? String ?? ""
    let params = msg["params"] as? [String: Any] ?? [:]
    guard let id else { continue }   // notifications (e.g. notifications/initialized) need no reply
    switch method {
    case "initialize":
        let requested = params["protocolVersion"] as? String ?? "2025-06-18"
        send(["jsonrpc": "2.0", "id": id, "result": [
            "protocolVersion": requested,
            "capabilities": ["tools": ["listChanged": false]],
            "serverInfo": ["name": "agentkey", "version": "0.1.0"],
            "instructions": "Secrets require the user's Touch ID / Apple Watch approval on their Mac (may take up to 60s). Prefer run_with_secret so plaintext never enters your context."]])
    case "ping":
        send(["jsonrpc": "2.0", "id": id, "result": [:] as [String: Any]])
    case "tools/list":
        send(["jsonrpc": "2.0", "id": id, "result": ["tools": tools]])
    case "tools/call":
        let name = params["name"] as? String ?? ""
        let a = params["arguments"] as? [String: Any] ?? [:]
        send(["jsonrpc": "2.0", "id": id, "result": callTool(name, a)])
    default:
        send(["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "method not found: \(method)"]])
    }
}
