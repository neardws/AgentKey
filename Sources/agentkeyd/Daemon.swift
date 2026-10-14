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
    /// P2P sync runtime (identity + replica under AKPaths.home/sync). nil if it failed to load.
    lazy var sync: SyncNode? = try? SyncNode(dir: AKPaths.syncDir, deviceName: ProcessInfo.processInfo.environment["AGENTKEY_DEVICE_NAME"] ?? ProcessInfo.processInfo.hostName)
    var syncPort: UInt16 = SyncNode.defaultPort
    var extraHosts: [String] = []
    /// Bonjour instance name when this node advertises on the LAN (nil = not advertising).
    var bonjourName: String?
    var bonjourListener: AnyObject?
    var netDisabled = false
    var netStarted = false
    var isSyncNode = false

    /// Start the connectivity runtime (STUN, UDP punching, DHT rendezvous) once a replica exists.
    func startNetIfNeeded() {
        guard !netDisabled, !netStarted, let node = sync, node.replica != nil else { return }
        let cfg = NetConfig.load(AKPaths.syncDir.appendingPathComponent("net.json"))
        do {
            let net = try NetRuntime(node: node, config: cfg, tcpPort: syncPort)
            net.bonjourName = bonjourName
            net.listensTCP = isSyncNode
            net.log = { print("net: \($0)") }
            net.beforeServe = { [weak self] in self?.reconcileVault() }
            net.afterServe = { [weak self] in self?.reconcileVault() }
            node.net = net; netStarted = true
            net.startBackground()
            print("agentkeyd net: udp \(net.mux.localPort), dht \(cfg.dht ? "on" : "off"), stun \(cfg.stunServers.count) server(s)\(cfg.relay.map { ", relay " + $0 } ?? "")")
        } catch { print("agentkeyd net: disabled (\(error))") }
    }

    /// Reconcile vault file <-> sync replica when the vault is unlocked (no-op when locked).
    @discardableResult
    func reconcileVault() -> (Int, Int)? {
        guard let node = sync, node.replica != nil else { return nil }
        return try? withVault { try node.reconcile(vault: $0) }
    }

    func requireSync() throws -> SyncNode {
        guard let n = sync else { throw RPCError(.internalError, "sync state could not be loaded from \(AKPaths.syncDir.path)") }
        return n
    }

    /// Human-only approval (Touch ID / Apple Watch) for sync/device/backup operations.
    func humanApprove(_ reason: String, ref: String, agent: String, conn: UnixConnection, peer: (uid: UInt32, pid: Int32?)) async throws {
        let code = PromptSanitizer.correlationCode()
        log("\(ref)_request", agent: agent, ref: ref, code: code, detail: reason, peer: peer)
        try? conn.send(RPCMessage(id: nil, method: "progress", params: ["state": "awaiting_approval", "code": code, "ref": ref,
            "hint": "Approve: \(reason) — Touch ID or Apple Watch"]))
        var areq = ApprovalRequest(agent: agent, secretName: ref, mode: .fill, code: code, command: nil)
        areq.customReason = reason
        do { try await coordinator.approve(areq, timeout: 60) }
        catch let e as ApprovalError {
            log("\(ref)_denied", agent: agent, ref: ref, code: code, detail: e.description, peer: peer)
            throw RPCError(e.isDenied ? .userDenied : .noApprover, e.description)
        }
        log("\(ref)_approved", agent: agent, ref: ref, code: code, peer: peer)
    }

    func jsonString<T: Encodable>(_ v: T) throws -> String {
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = .sortedKeys
        return String(decoding: try e.encode(v), as: UTF8.self)
    }

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

            // MARK: P2P sync (no external services; see docs/DESIGN.zh.md A5)
            case "sync.status", "device.list":
                let node = try requireSync()
                return RPCMessage(id: req.id, result: ["status": try jsonString(node.status())])

            case "net.probe":
                let node = try requireSync()
                startNetIfNeeded()
                guard let net = node.net else { throw RPCError(.notFound, netDisabled ? "networking disabled (--no-net)" : SyncNodeError.notInitialized.description) }
                return RPCMessage(id: req.id, result: ["probe": try jsonString(net.probe())])

            case "sync.signal.export":
                let node = try requireSync(); startNetIfNeeded()
                guard let net = node.net, let r = node.replica else { throw RPCError(.notFound, SyncNodeError.notInitialized.description) }
                let q = req.params["to"]
                var blobs: [[String: String]] = []
                for d in r.trust.devices.values where d.revokedAt == nil && d.deviceID != node.identity.deviceID.raw {
                    if let q, !(d.deviceID.hasPrefix(q.lowercased()) || d.name == q) { continue }
                    blobs.append(["device": d.deviceID, "name": d.name, "blob": try net.exportSignal(peer: d.deviceID)])
                }
                if blobs.isEmpty { throw RPCError(.notFound, "no matching paired device") }
                return RPCMessage(id: req.id, result: ["signals": try jsonString(blobs)])

            case "sync.signal.import":
                let node = try requireSync(); startNetIfNeeded()
                guard let net = node.net, let blob = req.params["blob"] else { throw RPCError(.usage, "blob required") }
                let (peer, rec) = try net.importSignal(blob)
                return RPCMessage(id: req.id, result: ["device": peer, "name": node.replica?.trust.devices[peer]?.name ?? "", "candidates": try jsonString(rec.c), "nat": rec.n])

            case "sync.now":
                let node = try requireSync()
                guard node.replica != nil else { throw RPCError(.notFound, SyncNodeError.notInitialized.description) }
                startNetIfNeeded()
                let via = ConnectVia(rawValue: req.params["via"] ?? "auto") ?? .auto
                if Discovery.supported && req.params["discover"] != "false" {
                    try? node.learnDiscovered(Discovery.browse(timeout: 2).nodes)
                }
                let pre = reconcileVault()
                let res = try node.syncNow(via: via)
                let post = reconcileVault()
                var peers: [[String: String]] = []
                for (p, r) in res.sorted(by: { $0.key < $1.key }) {
                    let name = node.replica?.trust.devices[p]?.name ?? p
                    switch r {
                    case .success(let s): peers.append(["device": p, "name": name, "ok": "true", "received": String(s.received), "sent": String(s.sent), "conflicts": String(s.conflicts)])
                    case .failure(let e): peers.append(["device": p, "name": name, "ok": "false", "error": "\(e)"])
                    }
                }
                log("sync_now", agent: agent, detail: "\(peers.count) peer(s)", peer: peer)
                return RPCMessage(id: req.id, result: ["peers": try jsonString(peers), "diagnostics": try jsonString(node.lastDiagnostics), "via": via.rawValue, "vaultUnlocked": String(pre != nil),
                                                       "toReplica": String((pre?.0 ?? 0) + (post?.0 ?? 0)), "toVault": String((pre?.1 ?? 0) + (post?.1 ?? 0))])

            case "sync.discover":
                let node = try requireSync()
                let t = Double(req.params["timeout"] ?? "") ?? 3
                let r = Discovery.browse(timeout: min(max(t, 0.5), 15))
                let nodes = Discovery.annotate(r.nodes, trust: node.replica?.trust)
                if req.params["learn"] != "false" { try? node.learnDiscovered(nodes) }
                var out = ["nodes": try jsonString(nodes), "supported": String(Discovery.supported)]
                if let e = r.error { out["error"] = e }
                return RPCMessage(id: req.id, result: out)

            case "device.pair.offer":
                // Show a one-time pairing code on THIS device (normally the home node). Human-only.
                let node = try requireSync()
                if node.replica == nil {
                    guard let vid = try? Vault.vaultID(at: AKPaths.vault) else { throw RPCError(.notFound, "no vault; run `agentkey init` first") }
                    _ = try node.initHome(vaultID: vid)
                    reconcileVault()
                }
                try await humanApprove("show a pairing code that lets a new device join this vault", ref: "device_pair_offer", agent: agent, conn: conn, peer: peer)
                // Bonjour name first (LAN, survives DHCP changes), then explicit hosts, then IPs as fallback.
                var hosts: [String] = []
                if let b = bonjourName { hosts.append(SyncEndpoint.bonjourPrefix + b) }
                if let h = req.params["hosts"] { hosts += h.split(separator: ",").map(String.init) }
                hosts += extraHosts
                hosts += LocalAddresses.ipv6Global()
                hosts += LocalAddresses.ipv4()
                let ttl = TimeInterval(req.params["ttl"].flatMap(Int.init) ?? 600)
                let p = try node.makeOffer(hosts: hosts, port: syncPort, ttl: ttl)
                return RPCMessage(id: req.id, result: ["uri": p.uri, "fingerprint": p.fingerprint, "expires": ISO8601DateFormatter().string(from: p.expires),
                                                       "hosts": p.hosts.joined(separator: ","), "port": String(p.port)])

            case "device.pair.join":
                let node = try requireSync()
                guard let uri = req.params["uri"], let payload = try? PairingPayload(uri: uri) else { throw RPCError(.usage, "invalid pairing code") }
                guard let vid = try? Vault.vaultID(at: AKPaths.vault) else { throw RPCError(.notFound, "no local vault; run `agentkey init` first") }
                _ = vid   // local vault id may differ from the group's; the bridge merges items by id
                try await humanApprove("join the sync group of \(PromptSanitizer.clean(payload.nodeName, max: 40)) (fingerprint \(payload.fingerprint))", ref: "device_pair_join", agent: agent, conn: conn, peer: peer)
                do { _ = try node.join(payload) } catch { throw RPCError(.userDenied, "pairing failed: \(error)") }
                let r = reconcileVault()
                startNetIfNeeded()
                _ = try? node.syncNow(); reconcileVault()
                log("device_paired", agent: agent, ref: payload.fingerprint, peer: peer)
                return RPCMessage(id: req.id, result: ["ok": "true", "deviceID": node.identity.deviceID.raw, "fingerprint": node.identity.fingerprint,
                                                       "vaultUnlocked": String(r != nil)])

            case "device.revoke":
                let node = try requireSync()
                guard let q = req.params["device"], let st = Optional(node.status()),
                      let d = st.devices.first(where: { $0.deviceID == q || $0.deviceID.hasPrefix(q.lowercased()) || $0.name == q || $0.fingerprint.replacingOccurrences(of: "-", with: "").hasPrefix(q.uppercased().replacingOccurrences(of: "-", with: "")) })
                else { throw RPCError(.notFound, "no such device") }
                try await humanApprove("revoke device \(d.name) (\(d.fingerprint)) and rotate the vault key", ref: "device_revoke", agent: agent, conn: conn, peer: peer)
                do { try node.revoke(d.deviceID) } catch { throw RPCError(.usage, "\(error)") }
                return RPCMessage(id: req.id, result: ["ok": "true", "device": d.deviceID, "keyVersion": String(node.status().keyVersion)])

            case "backup.export":
                guard let path = req.params["path"], let pass = req.params["passphrase"] else { throw RPCError(.usage, "path and passphrase required") }
                guard pass.count >= 12 else { throw RPCError(.usage, BackupError.weakPassphrase.description) }
                _ = try withVault { _ in () }
                try await humanApprove("export an encrypted backup of the whole vault to \(PromptSanitizer.clean(path, max: 80))", ref: "backup_export", agent: agent, conn: conn, peer: peer)
                let items = try withVault { try $0.items() }
                let blob = try BackupFile.create(items: items, trust: sync?.replica?.trust, passphrase: pass, createdBy: ProcessInfo.processInfo.hostName)
                guard FileManager.default.createFile(atPath: path, contents: blob, attributes: [.posixPermissions: 0o600]) else { throw RPCError(.usage, "cannot write \(path)") }
                return RPCMessage(id: req.id, result: ["ok": "true", "path": path, "items": String(items.count)])

            case "backup.restore":
                guard let path = req.params["path"], let pass = req.params["passphrase"] else { throw RPCError(.usage, "path and passphrase required") }
                guard let data = FileManager.default.contents(atPath: path) else { throw RPCError(.notFound, "cannot read \(path)") }
                _ = try withVault { _ in () }
                let r: (items: [VaultItem], trust: TrustState?, header: BackupFile)
                do { r = try BackupFile.restore(data, passphrase: pass) } catch { throw RPCError(.userDenied, "\(error)") }
                try await humanApprove("restore \(r.items.count) item(s) from backup made \(ISO8601DateFormatter().string(from: r.header.createdAt))", ref: "backup_restore", agent: agent, conn: conn, peer: peer)
                let n = try withVault { v -> (Int, Int) in
                    var added = 0, updated = 0
                    for i in r.items {
                        if let cur = try v.item(id: i.id) { if cur.updatedAt < i.updatedAt { try v.put(i); updated += 1 } }
                        else { try v.put(i); added += 1 }
                    }
                    return (added, updated)
                }
                reconcileVault()
                return RPCMessage(id: req.id, result: ["ok": "true", "added": String(n.0), "updated": String(n.1), "inBackup": String(r.items.count)])

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

public enum AgentKeyVersion { public static let string = "0.4.0" }
