import XCTest
@testable import AgentKeyCore

final class HygieneTests: XCTestCase {
    let key = SymmetricKey(size: .bits256)
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    func daysAgo(_ d: Double) -> Date { now.addingTimeInterval(-d * 86_400) }

    func fixtureItems() -> [VaultItem] {
        var a = VaultItem.login(title: "Site A", username: "neil", password: "Shared-Pass-2024!x", url: "https://a.example.com")
        var b = VaultItem.login(title: "Site B", username: "neil", password: "Shared-Pass-2024!x", url: "https://b.example.com")
        let weak = VaultItem.login(title: "Weak", username: "n", password: "letmein", url: "https://weak.example.com")
        var d1 = VaultItem.login(title: "Dup 1", username: "Neil", password: "Dup-One-Strong-77$q", url: "https://www.dup.example.com/login")
        var d2 = VaultItem.login(title: "Dup 2", username: "neil", password: "Dup-Two-Strong-88$q", url: "https://dup.example.com")
        var stale = VaultItem.apiToken(title: "Old Token", token: "tok-VERY-long-random-0123456789")
        var gh = VaultItem.login(title: "GitHub", username: "neil", password: "Gh-Strong-Pass-99&z", url: "https://github.com")
        var trashed = VaultItem.login(title: "Gone", username: "x", password: "Trash-Pass-55%%qq", url: "https://gone.example.com")
        for i in [\VaultItem.createdAt, \VaultItem.updatedAt] {
            a[keyPath: i] = daysAgo(10); b[keyPath: i] = daysAgo(10); d1[keyPath: i] = daysAgo(50); d2[keyPath: i] = daysAgo(5)
            stale[keyPath: i] = daysAgo(900); gh[keyPath: i] = daysAgo(1); trashed[keyPath: i] = daysAgo(100)
        }
        d1.lastUsedAt = daysAgo(1)        // most recently used → kept on merge
        trashed.trashedAt = daysAgo(60)
        var w = weak; w.createdAt = daysAgo(1); w.updatedAt = daysAgo(1)
        return [a, b, w, d1, d2, stale, gh, trashed]
    }

    func testEntropy() {
        XCTAssertLessThan(VaultHealth.entropyBits("password"), 15)
        XCTAssertLessThan(VaultHealth.entropyBits("aaaaaaaaaaaa"), VaultHealth.entropyBits("a8#Kq2!zP0wL"))
        XCTAssertGreaterThan(VaultHealth.entropyBits(PasswordGenerator.generate()), 100)
        XCTAssertLessThan(VaultHealth.entropyBits("abcd1234"), 45)
    }

    func testFindings() throws {
        let items = fixtureItems()
        let r = VaultHealth.analyze(items, hmacKey: key, now: now)
        func f(_ k: FindingKind) -> [HealthFinding] { r.findings.filter { $0.kind == k } }
        let title = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0.title) })

        XCTAssertEqual(f(.reused).count, 1)
        XCTAssertEqual(Set(f(.reused)[0].itemIDs.map { title[$0]! }), ["Site A", "Site B"])
        XCTAssertEqual(f(.weak).map { title[$0.itemIDs[0]]! }, ["Weak"])
        XCTAssertEqual(f(.weak)[0].severity, .high)
        XCTAssertEqual(Set(f(.duplicate).flatMap(\.itemIDs).map { title[$0]! }), ["Dup 1", "Dup 2"])
        XCTAssertEqual(f(.stale).map { title[$0.itemIDs[0]]! }, ["Old Token"])
        XCTAssertEqual(f(.oldPassword).map { title[$0.itemIDs[0]]! }, ["Old Token"])
        XCTAssertEqual(f(.missingTOTP).map { title[$0.itemIDs[0]]! }, ["GitHub"])
        XCTAssertEqual(f(.trashNotPurged).map { title[$0.itemIDs[0]]! }, ["Gone"])
        XCTAssertEqual(r.itemCount, 7)
        XCTAssertLessThan(r.score, 100)
        XCTAssertEqual(r.findings.first?.severity, .high)

        // no secret material in the report, and group ids are keyed (differ across vault keys)
        let json = String(decoding: try JSONEncoder().encode(r), as: UTF8.self)
        for i in items { for fl in i.fields where fl.concealed { XCTAssertFalse(json.contains(fl.value), fl.value) } }
        XCTAssertFalse(json.contains(Data(SHA256.hash(data: Data("Shared-Pass-2024!x".utf8))).hex.prefix(12)))
        let r2 = VaultHealth.analyze(items, hmacKey: SymmetricKey(size: .bits256), now: now)
        XCTAssertNotEqual(r2.findings.first { $0.kind == .reused }?.groupID, f(.reused)[0].groupID)
    }

    func testSuggestAndPartialApplyIsReversible() throws {
        let items = fixtureItems()
        let byTitle = Dictionary(uniqueKeysWithValues: items.map { ($0.title, $0) })
        let report = VaultHealth.analyze(items, hmacKey: key, now: now)
        let plan = CleanupPlanner.suggest(from: report, items: items, createdBy: "claude-code")
        XCTAssertEqual(plan.status, .pending)
        try CleanupPlanner.validate(plan, items: items)
        let merge = try XCTUnwrap(plan.actions.first { $0.kind == .merge })
        XCTAssertEqual(merge.keep, byTitle["Dup 1"]!.id)
        XCTAssertTrue(plan.actions.contains { $0.kind == .flagRotation && $0.itemIDs.contains(byTitle["Weak"]!.id) })
        XCTAssertTrue(plan.actions.contains { $0.kind == .purge })
        // each item flagged for rotation at most once
        let flagged = plan.actions.filter { $0.kind == .flagRotation }.flatMap(\.itemIDs)
        XCTAssertEqual(flagged.count, Set(flagged).count)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(plan), as: UTF8.self).contains("Shared-Pass"))

        // partially approve: only the merge + archive
        let approved: Set<String> = Set(plan.actions.filter { $0.kind == .merge || $0.kind == .archive }.map(\.id))
        let res = try CleanupPlanner.apply(plan, approved: approved, items: items, now: now)
        XCTAssertEqual(res.plan.status, .partiallyApplied)
        XCTAssertTrue(res.purge.isEmpty, "purge was not approved")
        let changed = Dictionary(uniqueKeysWithValues: res.changed.map { ($0.title, $0) })
        let kept = try XCTUnwrap(changed["Dup 1"])
        XCTAssertTrue(kept.urls.contains("https://dup.example.com"))
        XCTAssertTrue(kept.history?.contains { $0.fields.contains { $0.value == "Dup-Two-Strong-88$q" } } ?? false,
                      "the merged-away password is preserved in history")
        let gone = try XCTUnwrap(changed["Dup 2"])
        XCTAssertNotNil(gone.trashedAt); XCTAssertTrue(gone.tags.contains("merged"))
        XCTAssertNotNil(changed["Old Token"]?.archivedAt)
        XCTAssertNil(changed["Weak"], "rotation flag not approved")

        // cannot apply twice
        XCTAssertThrowsError(try CleanupPlanner.apply(res.plan, approved: nil, items: items))

        // reversible: restore plan brings the merged-away item back
        let undo = CleanupPlan(createdBy: "neil", title: "undo", actions: [PlanAction(id: "a1", kind: .restore, itemIDs: [gone.id], reason: "undo")])
        let after = items.map { i in res.changed.first { $0.id == i.id } ?? i }
        let u = try CleanupPlanner.apply(undo, approved: nil, items: after, now: now)
        XCTAssertNil(u.changed.first?.trashedAt)
        XCTAssertEqual(u.plan.status, .applied)
    }

    func testValidationRejectsBadPlans() {
        let items = fixtureItems()
        let a = items[0].id
        let bad: [[PlanAction]] = [
            [],
            [PlanAction(id: "a1", kind: .trash, itemIDs: [UUID()], reason: "unknown item")],
            [PlanAction(id: "a1", kind: .merge, itemIDs: [a], keep: a, reason: "merge of one")],
            [PlanAction(id: "a1", kind: .purge, itemIDs: [a], reason: "purge live item")],
            [PlanAction(id: "a1", kind: .addTags, itemIDs: [a], reason: "no tags")],
            [PlanAction(id: "a1", kind: .trash, itemIDs: [a], reason: "x"), PlanAction(id: "a1", kind: .archive, itemIDs: [a], reason: "dup id")],
        ]
        for acts in bad {
            XCTAssertThrowsError(try CleanupPlanner.validate(CleanupPlan(createdBy: "x", title: "t", actions: acts), items: items))
        }
    }

    func testVaultTracksRotationAndUsage() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("akh-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let kdf = KDFParams(algorithm: "pbkdf2-sha256", iterations: 1000, memoryKiB: nil, parallelism: nil, salt: AKRandom.bytes(16))
        let (v, _) = try Vault.create(at: dir.appendingPathComponent("v.akv"), password: "correct horse battery", kdf: kdf)
        var i = VaultItem.login(title: "S", username: "u", password: "first-password-1")
        try v.upsert(i)
        let t0 = try XCTUnwrap(try v.item(id: i.id)?.passwordChangedAt)
        i.fields[1].value = "second-password-2"
        try v.upsert(i)
        let after = try XCTUnwrap(try v.item(id: i.id))
        XCTAssertGreaterThanOrEqual(after.passwordChangedAt!, t0)
        XCTAssertEqual(after.history?.last?.fields.first?.value, "first-password-1")
        XCTAssertNil(after.lastUsedAt)
        try v.touch(id: i.id)
        XCTAssertNotNil(try v.item(id: i.id)?.lastUsedAt)
    }
}
