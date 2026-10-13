import Foundation
import AgentKeyCore
import AgentKeyIPC
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Holds the unlocked vault in memory and answers IPC requests.
final class Daemon: @unchecked Sendable {
    let coordinator = ApprovalCoordinator()
    private let lock = NSLock()
    private var vault: Vault?
    private var audit: AuditLog?
    let startedAt = Date()

    func withVault<T>(_ f: (Vault) throws -> T) throws -> T {
        try lock.withLock {
        guard let v = vault else { throw RPCError(.locked, "vault is locked; run `agentkey unlock`") }
        try v.reload()
        return try f(v)
        }
    }

    func log(_ event: String, agent: String, ref: String? = nil, mode: String? = nil, code: String? = nil,
             detail: String? = nil, peer: (uid: UInt32, pid: Int32?)? = nil) {
        let a = lock.withLock { audit }
        do {
            let log = try a ?? AuditLog(url: AKPaths.audit)
            try log.append(event: event, agent: agent, ref: ref, mode: mode, code: code, detail: detail,
                           peerPID: peer?.pid, peerUID: peer?.uid)
        } catch {
            FileHandle.standardError.write(Data("audit write failed: \(error)\n".utf8))
        }
    }

    // MARK: request handling

    func handle(_ req: RPCRequest, conn: UnixConnection, peer: (uid: UInt32, pid: Int32?)) async -> RPCMessage {
        let agent = PromptSanitizer.clean(req.params["agent"] ?? "unknown", max: 64)
        do {
            switch req.method {
            case "hello", "status":
                let st = await coordinator.status()
                let locked = lock.withLock { vault == nil }
                return RPCMessage(id: req.id, result: [
                    "protocol": IPC.protocolID, "version": AgentKeyVersion.string, "locked": String(locked),
                    "touchIDReady": String(st.touchIDReady), "watchReady": String(st.watchReady), "detail": st.detail])

            case "unlock":
                guard let pw = req.params["password"] else { throw RPCError(.usage, "password required") }
                let url = AKPaths.vault
                let acct = try Vault.accountID(at: url)
                guard let sk = req.params["secretKey"].flatMap(SecretKey.init(formatted:)) ?? SecretKeyStore.load(account: acct)
                else { throw RPCError(.usage, "Secret Key not found in Keychain; pass it with --secret-key") }
                let v: Vault
                do { v = try Vault.unlock(at: url, password: pw, secretKey: sk) }
                catch { log("unlock_failed", agent: agent, peer: peer); throw RPCError(.userDenied, "\(error)") }
                let a = try AuditLog(url: AKPaths.audit, chainKey: v.auditKey)
                lock.withLock { vault = v; audit = a }
                log("unlock", agent: agent, peer: peer)
                return RPCMessage(id: req.id, result: ["ok": "true"])

            case "lock":
                log("lock", agent: agent, peer: peer)
                lock.withLock { vault = nil; audit = nil }
                return RPCMessage(id: req.id, result: ["ok": "true"])

            case "list":
                let items = try withVault { try $0.items() }.map(\.overview)
                let json = String(decoding: try JSONEncoder().encode(items), as: UTF8.self)
                log("list", agent: agent, detail: "\(items.count) items", peer: peer)
                return RPCMessage(id: req.id, result: ["items": json])

            case "release", "totp":
                guard let refS = req.params["ref"], let ref = ItemRef(refS) else { throw RPCError(.usage, "ref required") }
                let mode: ReleaseMode = req.method == "totp" ? .totp : (ReleaseMode(rawValue: req.params["mode"] ?? "") ?? .reveal)
                guard [.reveal, .run, .totp].contains(mode) else { throw RPCError(.usage, "mode \(mode.rawValue) not implemented yet") }
                let item = try withVault { v -> VaultItem in
                    do { return try v.resolve(ref) } catch { throw RPCError(.notFound, "\(error)") }
                }
                let fieldID = mode == .totp ? (ref.field ?? "totp") : ref.field
                guard let field = item.field(fieldID) else { throw RPCError(.notFound, "field \(fieldID ?? "(default)") not on item") }
                let refStr = ItemRef.make(title: item.title, field: field.id)
                let policy = AgentPolicy.load(AKPaths.policy)
                if case .deny(let why) = policy.evaluate(agent: agent, item: item, mode: mode) {
                    log("policy_denied", agent: agent, ref: refStr, mode: mode.rawValue, detail: why, peer: peer)
                    throw RPCError(.policyDenied, why)
                }
                let code = PromptSanitizer.correlationCode()
                log("request", agent: agent, ref: refStr, mode: mode.rawValue, code: code, detail: req.params["command"], peer: peer)
                try? conn.send(RPCMessage(id: nil, method: "progress",
                    params: ["state": "awaiting_approval", "code": code, "ref": refStr,
                             "hint": "Approve on the Mac with Touch ID or by double-clicking the Apple Watch side button"]))
                let areq = ApprovalRequest(agent: agent, secretName: "\(item.title)/\(field.label)", mode: mode, code: code, command: req.params["command"])
                do {
                    try await coordinator.approve(areq, timeout: TimeInterval(policy.approvalTimeoutSeconds))
                } catch let e as ApprovalError {
                    log("denied", agent: agent, ref: refStr, mode: mode.rawValue, code: code, detail: e.description, peer: peer)
                    switch e {
                    case .denied: throw RPCError(.userDenied, e.description)
                    case .timeout: throw RPCError(.timeout, e.description)
                    default: throw RPCError(.noApprover, e.description)
                    }
                }
                log("approved", agent: agent, ref: refStr, mode: mode.rawValue, code: code, peer: peer)
                if mode == .totp {
                    guard let t = TOTP(string: field.value) else { throw RPCError(.internalError, "field is not a TOTP secret") }
                    return RPCMessage(id: req.id, result: ["code": t.code(), "expiresIn": String(t.secondsRemaining()), "correlation": code])
                }
                return RPCMessage(id: req.id, result: ["value": Data(field.value.utf8).base64EncodedString(), "ref": refStr, "correlation": code])

            case "audit.verify":
                let k = lock.withLock { vault?.auditKey }
                switch try AuditLog.verify(AKPaths.audit, chainKey: k) {
                case .ok(let n): return RPCMessage(id: req.id, result: ["ok": "true", "count": String(n), "macChecked": String(k != nil)])
                case .broken(let s, let r): return RPCMessage(id: req.id, result: ["ok": "false", "seq": String(s), "reason": r])
                }

            default:
                throw RPCError(.usage, "unknown method \(req.method)")
            }
        } catch let e as RPCError {
            return RPCMessage(id: req.id, error: e)
        } catch {
            return RPCMessage(id: req.id, error: RPCError(.internalError, "\(error)"))
        }
    }

    func serve(_ conn: UnixConnection) {
        let peer = conn.peer()
        guard peer.uid == getuid() else {
            log("rejected_peer", agent: "?", detail: "uid \(peer.uid)", peer: peer); return
        }
        while true {
            guard let frame = try? conn.readFrame() else { return }
            let reply: RPCMessage
            if let req = try? JSONDecoder().decode(RPCRequest.self, from: frame) {
                let sem = DispatchSemaphore(value: 0)
                let box = Box<RPCMessage>()
                Task { box.value = await self.handle(req, conn: conn, peer: peer); sem.signal() }
                sem.wait()
                reply = box.value!
            } else {
                reply = RPCMessage(id: nil, error: RPCError(.usage, "malformed request"))
            }
            do { try conn.send(reply) } catch { return }
        }
    }
}

final class Box<T>: @unchecked Sendable { var value: T? }

public enum AgentKeyVersion { public static let string = "0.1.0" }
