import XCTest
@testable import AgentKeyCore

/// Fake CloudKit zone: last-writer-must-know-the-current-version (like CKRecord change tags).
final class FakeServer {
    var records: [UUID: SyncRecord] = [:]
    /// Upload; returns conflicts (server copy) when the client's base is stale.
    func save(_ recs: [SyncRecord], from r: SyncReplica) throws -> [SyncRecord] {
        var conflicts: [SyncRecord] = []
        for rec in recs {
            if let cur = records[rec.meta.id], r.base[rec.meta.id]?.stamp != cur.meta.stamp {
                conflicts.append(cur); continue
            }
            records[rec.meta.id] = rec
            try r.didSave(rec)
        }
        return conflicts
    }
    func sync(_ r: SyncReplica) throws {
        // fetch first, then push (and loop once for conflicts), like CKSyncEngine
        for rec in records.values where r.base[rec.meta.id]?.stamp != rec.meta.stamp { try r.receive(rec) }
        for _ in 0..<3 {
            let conflicts = try save(try r.outgoing(), from: r)
            if conflicts.isEmpty { break }
            for c in conflicts { try r.receive(c) }
        }
    }
}

final class SyncTests: XCTestCase {
    let key = SymmetricKey(size: .bits256)
    func pair() -> (SyncReplica, SyncReplica, FakeServer) {
        (SyncReplica(device: DeviceID("mac"), key: key), SyncReplica(device: DeviceID("iphone"), key: key), FakeServer())
    }
    func pw(_ i: VaultItem?) -> String? { i?.fields.first { $0.id == "password" }?.value }

    func testLamportClock() {
        var c = LamportClock(); c.tick(); c.observe(10); XCTAssertEqual(c.tick(), 11)
        XCTAssertLessThan(Stamp(lamport: 5, device: DeviceID("a")), Stamp(lamport: 5, device: DeviceID("b")))
        XCTAssertLessThan(Stamp(lamport: 4, device: DeviceID("z")), Stamp(lamport: 5, device: DeviceID("a")))
    }

    func testRecordEncryptionAndTombstone() throws {
        let item = VaultItem.login(title: "Site", username: "u", password: "p-secret")
        let meta = RecordMeta(id: item.id, revision: 1, stamp: Stamp(lamport: 1, device: DeviceID("a")))
        let rec = try SyncRecord.seal(item, meta: meta, key: key)
        XCTAssertFalse(String(decoding: rec.ciphertext!, as: UTF8.self).contains("p-secret"))
        XCTAssertEqual(try rec.open(key: key), item)
        XCTAssertThrowsError(try rec.open(key: SymmetricKey(size: .bits256)))
        var moved = rec; moved.meta.id = UUID()   // ciphertext bound to record id
        XCTAssertThrowsError(try moved.open(key: key))
        var tomb = meta; tomb.deleted = true
        XCTAssertNil(try SyncRecord.seal(item, meta: tomb, key: key).ciphertext)
    }

    func testDisjointFieldEditsBothSurvive() throws {
        let (a, b, s) = pair()
        var item = VaultItem.login(title: "GitHub", username: "neil", password: "old-pw", url: "https://github.com")
        a.write(item); try s.sync(a); try s.sync(b)
        XCTAssertEqual(b.item(item.id), item)

        item.fields[1].value = "new-pw"; a.write(item)               // Mac changes password
        var other = b.item(item.id)!; other.title = "GitHub (work)"; other.tags = ["work"]; b.write(other)  // iPhone renames
        try s.sync(a); try s.sync(b); try s.sync(a)
        for r in [a, b] {
            let m = r.item(item.id)
            XCTAssertEqual(pw(m), "new-pw"); XCTAssertEqual(m?.title, "GitHub (work)"); XCTAssertEqual(m?.tags, ["work"])
        }
        XCTAssertTrue(a.conflicts.isEmpty && b.conflicts.isEmpty)
        XCTAssertTrue(a.pending.isEmpty && b.pending.isEmpty)
    }

    func testSameFieldConflictHigherStampWinsLoserKeptInHistory() throws {
        let (a, b, s) = pair()
        let item = VaultItem.login(title: "Bank", username: "neil", password: "base-pw")
        a.write(item); try s.sync(a); try s.sync(b)
        var x = item; x.fields[1].value = "mac-pw"; a.write(x)
        var y = b.item(item.id)!; y.fields[1].value = "phone-pw"; b.write(y); b.write(y)  // b has higher lamport
        try s.sync(a); try s.sync(b); try s.sync(a)
        XCTAssertEqual(pw(a.item(item.id)), "phone-pw")
        XCTAssertEqual(pw(b.item(item.id)), "phone-pw")
        let hist = try XCTUnwrap(b.item(item.id)?.history)
        XCTAssertTrue(hist.contains { $0.fields.contains { $0.value == "mac-pw" } }, "losing value preserved")
        XCTAssertFalse(b.conflicts.isEmpty)
    }

    func testTagSetMerge() {
        XCTAssertEqual(MergeEngine.mergeList(["a", "b"], ["a", "b", "c"], ["b", "d"]), ["b", "c", "d"])
    }

    func testDeleteVsEditKeepsEditAndDeleteVsUnchangedDeletes() throws {
        let (a, b, s) = pair()
        let i1 = VaultItem.apiToken(title: "T1", token: "tok-1-original")
        let i2 = VaultItem.apiToken(title: "T2", token: "tok-2-original")
        a.write(i1); a.write(i2); try s.sync(a); try s.sync(b)
        a.delete(i1.id)                                              // delete vs edit
        var e = b.item(i1.id)!; e.fields[0].value = "tok-1-rotated"; b.write(e)
        b.delete(i2.id)                                              // delete vs unchanged
        try s.sync(a); try s.sync(b); try s.sync(a)
        for r in [a, b] {
            XCTAssertEqual(r.item(i1.id)?.fields[0].value, "tok-1-rotated")
            XCTAssertNil(r.item(i2.id))
            XCTAssertEqual(r.records[i2.id]?.meta.deleted, true, "tombstone retained")
        }
    }

    func testConvergenceRandomized() throws {
        var rng = SystemRandomNumberGenerator()
        let (a, b, s) = pair()
        let c = SyncReplica(device: DeviceID("ipad"), key: key)
        let seed = (0..<5).map { VaultItem.login(title: "S\($0)", username: "u", password: "p\($0)") }
        for i in seed { a.write(i) }
        try s.sync(a); try s.sync(b); try s.sync(c)
        for round in 0..<30 {
            for r in [a, b, c] {
                for _ in 0..<2 {
                    let live = r.liveItems
                    switch Int.random(in: 0..<10, using: &rng) {
                    case 0: if let x = live.randomElement(using: &rng) { r.delete(x.id) }
                    case 1: r.write(.login(title: "N\(round)\(r.device)", username: "u", password: "x"))
                    default:
                        if var x = live.randomElement(using: &rng) {
                            if Bool.random(using: &rng) { x.fields[x.fields.count - 1].value = "v\(round)\(r.device)" }
                            else { x.tags.append("t\(Int.random(in: 0..<3, using: &rng))") }
                            r.write(x)
                        }
                    }
                }
                if Bool.random(using: &rng) { try s.sync(r) }
            }
        }
        for _ in 0..<4 { for r in [a, b, c] { try s.sync(r) } }
        XCTAssertEqual(a.liveItems.map(\.id), b.liveItems.map(\.id))
        XCTAssertEqual(a.liveItems, c.liveItems)
        XCTAssertEqual(a.liveItems.map(\.fields), b.liveItems.map(\.fields))
        XCTAssertEqual(b.liveItems.map(\.fields), c.liveItems.map(\.fields))
        XCTAssertEqual(a.liveItems.map(\.tags), c.liveItems.map(\.tags))
        XCTAssertTrue(a.pending.isEmpty && b.pending.isEmpty && c.pending.isEmpty)
    }
}
