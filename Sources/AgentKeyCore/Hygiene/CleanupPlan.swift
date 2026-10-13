import Foundation

/// A structured, reviewable change proposal created by an agent (or the user). Nothing is
/// applied until a human approves with Touch ID / Apple Watch; approval can be partial.
/// Plans reference items by id only and contain no secret values.
public struct CleanupPlan: Codable, Equatable, Sendable {
    public enum Status: String, Codable, Sendable { case pending, applied, partiallyApplied = "partially_applied", rejected, expired }

    public var id: String
    public var createdAt: Date
    public var createdBy: String           // agent label (self-reported)
    public var title: String
    public var status: Status
    public var actions: [PlanAction]
    public var appliedAt: Date?
    public var vaultID: UUID?

    public init(createdBy: String, title: String, actions: [PlanAction], vaultID: UUID? = nil) {
        id = "plan-" + String(UUID().uuidString.prefix(8)).lowercased()
        createdAt = Date(); self.createdBy = createdBy; self.title = title
        status = .pending; self.actions = actions; self.vaultID = vaultID
    }
}

public struct PlanAction: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case merge            // keep `keep`, fold the others into it, trash the others
        case trash            // soft delete (restorable)
        case archive
        case restore          // undo trash / archive
        case flagRotation = "flag_rotation"   // add the "rotate" tag
        case addTags = "add_tags"
        case removeTags = "remove_tags"
        case purge            // permanently drop items that are already in trash
    }
    public enum State: String, Codable, Sendable { case pending, applied, skipped, rejected }

    public var id: String                  // "a1", "a2", …
    public var kind: Kind
    public var itemIDs: [UUID]
    public var keep: UUID?
    public var tags: [String]?
    public var reason: String
    public var state: State = .pending
    public var result: String?

    enum CodingKeys: String, CodingKey { case id, kind, itemIDs, keep, tags, reason, state, result }
    /// Lenient decoding for agent-supplied actions (state/result optional).
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(Kind.self, forKey: .kind)
        itemIDs = try c.decode([UUID].self, forKey: .itemIDs)
        keep = try c.decodeIfPresent(UUID.self, forKey: .keep)
        tags = try c.decodeIfPresent([String].self, forKey: .tags)
        reason = try c.decodeIfPresent(String.self, forKey: .reason) ?? ""
        state = try c.decodeIfPresent(State.self, forKey: .state) ?? .pending
        result = try c.decodeIfPresent(String.self, forKey: .result)
    }

    public init(id: String, kind: Kind, itemIDs: [UUID], keep: UUID? = nil, tags: [String]? = nil, reason: String) {
        self.id = id; self.kind = kind; self.itemIDs = itemIDs; self.keep = keep; self.tags = tags; self.reason = reason
    }
}

public enum PlanError: Error, CustomStringConvertible {
    case invalid(String), notPending(String)
    public var description: String {
        switch self { case .invalid(let s): return "invalid plan: \(s)"; case .notPending(let s): return "plan is not pending: \(s)" }
    }
}

public enum CleanupPlanner {
    /// Validate an agent-supplied plan against the current vault (unknown items, bad merges…).
    public static func validate(_ p: CleanupPlan, items: [VaultItem]) throws {
        let ids = Set(items.map(\.id))
        guard !p.actions.isEmpty else { throw PlanError.invalid("no actions") }
        guard p.actions.count <= 500 else { throw PlanError.invalid("too many actions") }
        guard Set(p.actions.map(\.id)).count == p.actions.count else { throw PlanError.invalid("duplicate action ids") }
        for a in p.actions {
            guard !a.itemIDs.isEmpty else { throw PlanError.invalid("\(a.id): no items") }
            for i in a.itemIDs where !ids.contains(i) { throw PlanError.invalid("\(a.id): unknown item \(i)") }
            switch a.kind {
            case .merge:
                guard let k = a.keep, a.itemIDs.contains(k), a.itemIDs.count >= 2 else { throw PlanError.invalid("\(a.id): merge needs keep ∈ items and ≥2 items") }
            case .addTags, .removeTags:
                guard let t = a.tags, !t.isEmpty, t.allSatisfy({ !$0.isEmpty && $0.count <= 64 }) else { throw PlanError.invalid("\(a.id): tags required") }
            case .purge:
                let byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
                guard a.itemIDs.allSatisfy({ byID[$0]?.isTrashed == true }) else { throw PlanError.invalid("\(a.id): purge only applies to trashed items") }
            default: break
            }
        }
    }

    /// Build a suggested plan from a health report (what an agent would typically propose).
    public static func suggest(from r: HealthReport, items: [VaultItem], createdBy: String) -> CleanupPlan {
        let byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        var actions: [PlanAction] = []
        func next() -> String { "a\(actions.count + 1)" }
        for f in r.findings {
            switch f.kind {
            case .duplicate:
                // keep the most recently used/updated entry
                let keep = f.itemIDs.max { a, b in
                    let da = max(byID[a]?.lastUsedAt ?? .distantPast, byID[a]?.updatedAt ?? .distantPast)
                    let db = max(byID[b]?.lastUsedAt ?? .distantPast, byID[b]?.updatedAt ?? .distantPast)
                    return da < db
                }
                actions.append(PlanAction(id: next(), kind: .merge, itemIDs: f.itemIDs, keep: keep, reason: f.detail))
            case .reused, .weak, .oldPassword:
                let ids = f.itemIDs.filter { !(byID[$0]?.tags.contains("rotate") ?? false) }
                if !ids.isEmpty { actions.append(PlanAction(id: next(), kind: .flagRotation, itemIDs: ids, reason: "\(f.kind.rawValue): \(f.detail)")) }
            case .stale:
                actions.append(PlanAction(id: next(), kind: .archive, itemIDs: f.itemIDs, reason: f.detail))
            case .trashNotPurged:
                actions.append(PlanAction(id: next(), kind: .purge, itemIDs: f.itemIDs, reason: f.detail))
            case .missingTOTP:
                actions.append(PlanAction(id: next(), kind: .addTags, itemIDs: f.itemIDs, tags: ["needs-2fa"], reason: f.detail))
            }
        }
        // collapse duplicate flag_rotation actions for the same item
        var seen = Set<UUID>()
        actions = actions.compactMap { a in
            guard a.kind == .flagRotation else { return a }
            var b = a; b.itemIDs = a.itemIDs.filter { seen.insert($0).inserted }
            return b.itemIDs.isEmpty ? nil : b
        }
        for i in actions.indices { actions[i].id = "a\(i + 1)" }
        return CleanupPlan(createdBy: createdBy, title: "Vault cleanup (\(actions.count) actions)", actions: actions)
    }

    /// Apply the approved subset of actions. Every change is reversible: merges and trash keep the
    /// data (trash + item history); purge only removes items already in trash.
    /// Returns updated items, ids to purge, and the plan with per-action states.
    public static func apply(_ plan: CleanupPlan, approved: Set<String>?, items: [VaultItem], now: Date = Date())
        throws -> (changed: [VaultItem], purge: [UUID], plan: CleanupPlan) {
        guard plan.status == .pending else { throw PlanError.notPending(plan.status.rawValue) }
        try validate(plan, items: items)
        var byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        var touched = Set<UUID>(), purge: [UUID] = []
        var p = plan
        for idx in p.actions.indices {
            let a = p.actions[idx]
            guard approved == nil || approved!.contains(a.id) else { p.actions[idx].state = .rejected; continue }
            func mutate(_ id: UUID, _ f: (inout VaultItem) -> Void) {
                guard var it = byID[id] else { return }
                f(&it); it.updatedAt = now; byID[id] = it; touched.insert(id)
            }
            switch a.kind {
            case .trash: a.itemIDs.forEach { mutate($0) { $0.trashedAt = now } }
            case .archive: a.itemIDs.forEach { mutate($0) { $0.archivedAt = now } }
            case .restore: a.itemIDs.forEach { mutate($0) { $0.trashedAt = nil; $0.archivedAt = nil } }
            case .flagRotation: a.itemIDs.forEach { mutate($0) { if !$0.tags.contains("rotate") { $0.tags.append("rotate"); $0.tags.sort() } } }
            case .addTags: a.itemIDs.forEach { mutate($0) { $0.tags = Array(Set($0.tags + (a.tags ?? []))).sorted() } }
            case .removeTags: a.itemIDs.forEach { mutate($0) { $0.tags.removeAll { (a.tags ?? []).contains($0) } } }
            case .purge:
                let ok = a.itemIDs.filter { byID[$0]?.isTrashed == true }
                purge += ok; ok.forEach { byID[$0] = nil; touched.remove($0) }
            case .merge:
                guard let keepID = a.keep, var keep = byID[keepID] else { p.actions[idx].state = .skipped; continue }
                for other in a.itemIDs where other != keepID {
                    guard let o = byID[other] else { continue }
                    for u in o.urls where !keep.urls.contains(u) { keep.urls.append(u) }
                    keep.tags = Array(Set(keep.tags + o.tags)).sorted()
                    if keep.notes == nil { keep.notes = o.notes }
                    else if let n = o.notes, !n.isEmpty, n != keep.notes { keep.notes = keep.notes! + "\n\n— merged from \(o.title):\n" + n }
                    // differing field values are kept in history, never dropped
                    let diverging = o.fields.filter { f in keep.fields.contains { $0.id == f.id && $0.value != f.value } }
                    if !diverging.isEmpty { keep.recordHistory("merged from \(o.title) (\(o.id.uuidString.prefix(8)))", fields: diverging) }
                    for f in o.fields where !keep.fields.contains(where: { $0.id == f.id }) { keep.fields.append(f) }
                    keep.lastUsedAt = [keep.lastUsedAt, o.lastUsedAt].compactMap { $0 }.max()
                    mutate(other) { $0.trashedAt = now; $0.tags = Array(Set($0.tags + ["merged"])).sorted() }
                }
                keep.updatedAt = now; byID[keepID] = keep; touched.insert(keepID)
            }
            p.actions[idx].state = .applied
        }
        let applied = p.actions.filter { $0.state == .applied }.count
        p.status = applied == 0 ? .rejected : applied == p.actions.count ? .applied : .partiallyApplied
        p.appliedAt = now
        return (touched.compactMap { byID[$0] }, purge, p)
    }
}

/// Plans are stored as JSON next to the vault (ids + reasons only, no secrets).
public enum PlanStore {
    public static var dir: URL { AKPaths.home.appendingPathComponent("plans", isDirectory: true) }
    static func url(_ id: String) throws -> URL {
        guard id.range(of: "^plan-[a-z0-9-]{1,40}$", options: .regularExpression) != nil else { throw PlanError.invalid("bad plan id") }
        return dir.appendingPathComponent(id + ".json")
    }
    public static func save(_ p: CleanupPlan) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let d = try Vault.encoder.encode(p)
        FileManager.default.createFile(atPath: try url(p.id).path, contents: d, attributes: [.posixPermissions: 0o600])
    }
    public static func load(_ id: String) throws -> CleanupPlan {
        try Vault.decoder.decode(CleanupPlan.self, from: Data(contentsOf: try url(id)))
    }
    public static func list() -> [CleanupPlan] {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "json" }
            .compactMap { try? Vault.decoder.decode(CleanupPlan.self, from: Data(contentsOf: $0)) }
            .sorted { $0.createdAt > $1.createdAt }
    }
}
