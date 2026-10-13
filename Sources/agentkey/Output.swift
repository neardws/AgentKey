import Foundation
import AgentKeyIPC
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Stable, machine-readable error codes for `--json` output (and exit codes).
enum CLIError: String {
    case usage = "USAGE", policyDenied = "POLICY_DENIED", userDenied = "USER_DENIED", timeout = "TIMEOUT",
         noApprover = "NO_APPROVER", daemonUnavailable = "DAEMON_UNAVAILABLE", locked = "LOCKED",
         notFound = "NOT_FOUND", badPassword = "BAD_PASSWORD", exists = "ALREADY_EXISTS",
         auditBroken = "AUDIT_BROKEN", spawnFailed = "SPAWN_FAILED", internalError = "INTERNAL"

    var exitCode: Int32 {
        switch self {
        case .usage: return 64
        case .policyDenied: return 65
        case .userDenied, .badPassword: return 66
        case .timeout: return 67
        case .noApprover: return 68
        case .daemonUnavailable, .locked: return 69
        case .notFound: return 70
        case .exists, .auditBroken, .spawnFailed, .internalError: return 1
        }
    }

    init(_ rpc: RPCError) {
        switch rpc.kind {
        case .usage: self = .usage
        case .policyDenied: self = .policyDenied
        case .userDenied: self = rpc.message.contains("wrong master password") ? .badPassword : .userDenied
        case .timeout: self = .timeout
        case .noApprover: self = .noApprover
        case .locked: self = rpc.message.contains("not reachable") ? .daemonUnavailable : .locked
        case .notFound: self = .notFound
        case .internalError: self = .internalError
        }
    }
}

/// Output mode. JSON when `--json`, `AGENTKEY_OUTPUT=json`, or (for metadata commands)
/// when stdout is not a terminal — agents get JSON without asking. `--text` / `AGENTKEY_OUTPUT=text` forces text.
enum Out {
    nonisolated(unsafe) static var json = false
    /// When true, JSON documents (including errors) go to stderr because stdout belongs to a child (exec).
    nonisolated(unsafe) static var jsonToStderr = false

    static func decide(explicitJSON: Bool, explicitText: Bool, autoJSONWhenPiped: Bool) {
        let env = ProcessInfo.processInfo.environment["AGENTKEY_OUTPUT"]?.lowercased()
        if explicitText || env == "text" { json = false }
        else if explicitJSON || env == "json" { json = true }
        else { json = autoJSONWhenPiped && isatty(STDOUT_FILENO) == 0 }
    }

    static func encode(_ obj: Any) -> Data {
        (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data("{}".utf8)
    }

    static func emit(_ obj: [String: Any]) {
        var o = obj; if o["ok"] == nil { o["ok"] = true }
        let fh = jsonToStderr ? FileHandle.standardError : FileHandle.standardOutput
        fh.write(encode(o) + Data([0x0a]))
    }

    static func warn(_ message: String, code: String, extra: [String: Any] = [:]) {
        if json {
            var o: [String: Any] = ["warning": ["code": code, "message": message]]
            o.merge(extra) { a, _ in a }
            FileHandle.standardError.write(encode(o) + Data([0x0a]))
        } else {
            FileHandle.standardError.write(Data("agentkey: warning: \(message)\n".utf8))
        }
    }

    static func fail(_ message: String, _ e: CLIError) -> Never {
        if json {
            let o: [String: Any] = ["ok": false, "error": ["code": e.rawValue, "exit": Int(e.exitCode), "message": message]]
            (jsonToStderr ? FileHandle.standardError : FileHandle.standardOutput).write(encode(o) + Data([0x0a]))
        } else {
            FileHandle.standardError.write(Data("agentkey: \(message)\n".utf8))
        }
        exit(e.exitCode)
    }
}
