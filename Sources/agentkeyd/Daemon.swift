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
                _ = try? withVault { try $0.touch(id: item.id) }
                if mode == .totp {
                    guard let t = TOTP(string: field.value) else { throw RPCError(.internalError, "field is not a TOTP secret") }
                    return RPCMessage(id: req.id, result: ["code": t.code(), "expiresIn": String(t.secondsRemaining()), "correlation": code])
                }
                return RPCMessage(id: req.id, result: ["value": Data(field.value.utf8).base64EncodedString(), "ref": refStr, "correlation": code])

            case "health":
                var opts = HealthOptions()
                if let d = req.params["staleDays"].flatMap(Int.init) { opts.staleDays = d }
                if let d = req.params["rotationDays"].flatMap(Int.init) { opts.rotationDays = d }
                let report = try withVault { v in VaultHealth.analyze(try v.items(), hmacKey: v.healthKey, options: opts) }
                log("health", agent: agent, detail: "\(report.findings.count) findings", peer: peer)
                return RPCMessage(id: req.id, result: ["report": String(decoding: try Vault.encoder.encode(report), as: UTF8.self)])

            case "plan.create":
                // Agents may PROPOSE. Either supply actions JSON, or "auto" to derive from health.
                let (plan, vid): (CleanupPlan, UUID) = try withVault { v in
                    let items = try v.items()
                    var p: CleanupPlan
                    if let a = req.params["actions"] {
                        let acts = try Vault.decoder.decode([PlanAction].self, from: Data(a.utf8))
                        p = CleanupPlan(createdBy: agent, title: PromptSanitizer.clean(req.params["title"] ?? "Cleanup plan", max: 80), actions: acts)
                    } else {
                        p = CleanupPlanner.suggest(from: VaultHealth.analyze(items, hmacKey: v.healthKey), items: items, createdBy: agent)
                    }
                    for i in p.actions.indices { p.actions[i].state = .pending; p.actions[i].result = nil }
                    do { try CleanupPlanner.validate(p, items: items) } catch { throw RPCError(.usage, "\(error)") }
                    return (p, v.file.vaultID)
                }
                var p = plan; p.vaultID = vid
                try PlanStore.save(p)
                log("plan_created", agent: agent, ref: p.id, detail: "\(p.actions.count) actions", peer: peer)
                return RPCMessage(id: req.id, result: ["plan": String(decoding: try Vault.encoder.encode(p), as: UTF8.self)])

            case "plan.show":
                if let id = req.params["id"] {
                    guard let p = try? PlanStore.load(id) else { throw RPCError(.notFound, "no plan \(id)") }
                    return RPCMessage(id: req.id, result: ["plan": String(decoding: try Vault.encoder.encode(p), as: UTF8.self)])
                }
                return RPCMessage(id: req.id, result: ["plans": String(decoding: try Vault.encoder.encode(PlanStore.list()), as: UTF8.self)])

            case "plan.apply":
                // Applying is a human decision: always gated by Touch ID / Apple Watch.
                guard let id = req.params["id"], var plan = try? PlanStore.load(id) else { throw RPCError(.notFound, "no plan") }
                guard plan.status == .pending else { throw RPCError(.usage, "plan is \(plan.status.rawValue)") }
                let approved = req.params["actions"].map { Set($0.split(separator: ",").map(String.init)) }
                if let a = approved, let bad = a.first(where: { x in !plan.actions.contains { $0.id == x } }) {
                    throw RPCError(.usage, "unknown action \(bad)")
                }
                let n = approved?.count ?? plan.actions.count
                let code = PromptSanitizer.correlationCode()
                log("plan_apply_request", agent: agent, ref: id, code: code, detail: "\(n) actions", peer: peer)
                try? conn.send(RPCMessage(id: nil, method: "progress", params: ["state": "awaiting_approval", "code": code, "ref": id,
                    "hint": "Approve applying \(n) cleanup action(s) with Touch ID or Apple Watch"]))
                var areq = ApprovalRequest(agent: agent, secretName: id, mode: .fill, code: code, command: nil)
                areq.customReason = "apply \(n) vault cleanup action(s) from plan \(id) proposed by \(plan.createdBy)"
                do { try await coordinator.approve(areq, timeout: 60) }
                catch let e as ApprovalError {
                    log("plan_apply_denied", agent: agent, ref: id, code: code, detail: e.description, peer: peer)
                    throw RPCError(e.isDenied ? .userDenied : .noApprover, e.description)
                }
                let res = try withVault { v -> (CleanupPlan, Int, Int) in
                    let r = try CleanupPlanner.apply(plan, approved: approved, items: try v.items())
                    for item in r.changed { try v.upsert(item) }
                    for pid in r.purge { try v.delete(id: pid) }
                    return (r.plan, r.changed.count, r.purge.count)
                }
                plan = res.0
                try PlanStore.save(plan)
                for a in plan.actions {
                    log("plan_action_\(a.state.rawValue)", agent: agent, ref: id, mode: a.kind.rawValue, code: code,
                        detail: "\(a.id) items=\(a.itemIDs.map { String($0.uuidString.prefix(8)) }.joined(separator: ","))", peer: peer)
                }
                return RPCMessage(id: req.id, result: ["plan": String(decoding: try Vault.encoder.encode(plan), as: UTF8.self),
                                                       "changed": String(res.1), "purged": String(res.2)])

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
