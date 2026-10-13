// CloudKit transport (CKSyncEngine, private database, custom zone). Apple platforms only.
// STATUS: compile-able skeleton — NOT yet validated on a device. See TODO(mac) markers.
#if canImport(CloudKit)
import CloudKit
import Foundation

@available(macOS 14.0, iOS 17.0, *)
public final class CloudKitSyncAdapter: CKSyncEngineDelegate, @unchecked Sendable {
    public static let containerID = "iCloud.com.neardws.agentkey"
    public static let zoneID = CKRecordZone.ID(zoneName: "AgentKeyVault", ownerName: CKCurrentUserDefaultName)
    static let recordType = "VaultRecord"

    // CKRecord field names. Only ciphertext + non-secret sync metadata leave the device.
    enum F { static let ct = "ct", rev = "rev", lamport = "lamport", device = "device", deleted = "deleted", keyVersion = "kv" }

    let store: SyncRecordStore
    let container: CKContainer
    private var engine: CKSyncEngine!

    public init(store: SyncRecordStore, containerIdentifier: String = CloudKitSyncAdapter.containerID) {
        self.store = store
        self.container = CKContainer(identifier: containerIdentifier)
        var state: CKSyncEngine.State.Serialization? = nil
        if let d = store.loadEngineState() {
            state = try? JSONDecoder().decode(CKSyncEngine.State.Serialization.self, from: d)
        }
        let config = CKSyncEngine.Configuration(database: container.privateCloudDatabase,
                                                stateSerialization: state, delegate: self)
        // TODO(mac): decide automaticallySync (default true) vs manual fetch/send from the app lifecycle.
        engine = CKSyncEngine(config)
        engine.state.add(pendingDatabaseChanges: [.saveZone(CKRecordZone(zoneID: Self.zoneID))])
    }

    // MARK: local → engine

    /// Call after every local write/delete (the store has already bumped lamport/revision).
    public func enqueue(saved ids: [UUID] = [], deleted: [UUID] = []) {
        let changes: [CKSyncEngine.PendingRecordZoneChange] =
            ids.map { .saveRecord(recordID($0)) } + deleted.map { .saveRecord(recordID($0)) }
        // Deletions are uploaded as tombstone records (deleted=1, no ct) so other devices can
        // 3-way merge delete-vs-edit; hard `.deleteRecord` is only used for purge after retention.
        engine.state.add(pendingRecordZoneChanges: changes)
    }

    public func purge(_ ids: [UUID]) {
        engine.state.add(pendingRecordZoneChanges: ids.map { .deleteRecord(recordID($0)) })
    }

    public func syncNow() async throws {
        try await engine.fetchChanges()
        try await engine.sendChanges()
    }

    func recordID(_ id: UUID) -> CKRecord.ID { CKRecord.ID(recordName: id.uuidString, zoneID: Self.zoneID) }

    // MARK: SyncRecord <-> CKRecord

    func makeCKRecord(_ r: SyncRecord) -> CKRecord {
        let rec: CKRecord
        if let sys = store.systemFields(id: r.meta.id),
           let coder = try? NSKeyedUnarchiver(forReadingFrom: sys),
           let existing = CKRecord(coder: coder) {
            coder.finishDecoding()
            rec = existing                      // keeps the server change tag → proper conflict detection
        } else {
            rec = CKRecord(recordType: Self.recordType, recordID: recordID(r.meta.id))
        }
        rec[F.ct] = r.ciphertext as CKRecordValue?
        rec[F.rev] = Int64(r.meta.revision) as CKRecordValue
        rec[F.lamport] = Int64(bitPattern: r.meta.stamp.lamport) as CKRecordValue
        rec[F.device] = r.meta.stamp.device.raw as CKRecordValue
        rec[F.deleted] = Int64(r.meta.deleted ? 1 : 0) as CKRecordValue
        rec[F.keyVersion] = Int64(r.meta.keyVersion) as CKRecordValue
        return rec
    }

    static func syncRecord(from rec: CKRecord) -> SyncRecord? {
        guard let id = UUID(uuidString: rec.recordID.recordName),
              let lam = rec[F.lamport] as? Int64, let dev = rec[F.device] as? String else { return nil }
        let meta = RecordMeta(id: id, revision: Int((rec[F.rev] as? Int64) ?? 0),
                              stamp: Stamp(lamport: UInt64(bitPattern: lam), device: DeviceID(dev)),
                              deleted: ((rec[F.deleted] as? Int64) ?? 0) != 0,
                              keyVersion: Int((rec[F.keyVersion] as? Int64) ?? 1))
        return SyncRecord(meta: meta, ciphertext: rec[F.ct] as? Data)
    }

    func saveSystemFields(_ rec: CKRecord) {
        guard let id = UUID(uuidString: rec.recordID.recordName) else { return }
        let coder = NSKeyedArchiver(requiringSecureCoding: true)
        rec.encodeSystemFields(with: coder)
        coder.finishEncoding()
        store.setSystemFields(coder.encodedData, id: id)
    }

    // MARK: CKSyncEngineDelegate

    public func handleEvent(_ event: CKSyncEngine.Event, syncEngine: CKSyncEngine) async {
        switch event {
        case .stateUpdate(let e):
            if let d = try? JSONEncoder().encode(e.stateSerialization) { store.saveEngineState(d) }

        case .accountChange(let e):
            switch e.changeType {
            case .signIn: break
            case .signOut, .switchAccounts:
                // TODO(mac): surface in UI; never upload this vault into a different Apple ID silently.
                store.resetSyncState()
            @unknown default: break
            }

        case .fetchedRecordZoneChanges(let e):
            var reupload: [UUID] = []
            for m in e.modifications {
                saveSystemFields(m.record)
                if let r = Self.syncRecord(from: m.record), store.applyRemote(r) { reupload.append(r.meta.id) }
            }
            for d in e.deletions {
                if let id = UUID(uuidString: d.recordID.recordName) { store.applyRemoteDeletion(id: id); store.setSystemFields(nil, id: id) }
            }
            if !reupload.isEmpty { enqueue(saved: reupload) }

        case .sentRecordZoneChanges(let e):
            for rec in e.savedRecords {
                saveSystemFields(rec)
                if let r = Self.syncRecord(from: rec) { store.didSave(r) }
            }
            var retry: [UUID] = []
            for f in e.failedRecordSaves {
                guard let id = UUID(uuidString: f.record.recordID.recordName) else { continue }
                switch f.error.code {
                case .serverRecordChanged:
                    // someone else wrote first: merge with the server copy, then upload the result
                    if let server = f.error.serverRecord {
                        saveSystemFields(server)
                        if let r = Self.syncRecord(from: server) { _ = store.applyRemote(r) }
                    }
                    retry.append(id)
                case .zoneNotFound:
                    engine.state.add(pendingDatabaseChanges: [.saveZone(CKRecordZone(zoneID: Self.zoneID))])
                    retry.append(id)
                case .unknownItem:
                    store.setSystemFields(nil, id: id)   // record deleted on server; recreate
                    retry.append(id)
                case .networkFailure, .networkUnavailable, .zoneBusy, .serviceUnavailable, .requestRateLimited:
                    break                                // CKSyncEngine retries automatically
                default:
                    // TODO(mac): log + surface; quota exceeded etc.
                    break
                }
            }
            if !retry.isEmpty { enqueue(saved: retry) }

        case .fetchedDatabaseChanges(let e):
            for d in e.deletions where d.zoneID == Self.zoneID {
                // TODO(mac): zone deleted (user reset iCloud data) → ask before re-uploading everything
                store.resetSyncState()
            }

        default:
            break   // willFetchChanges, didFetchChanges, willSendChanges, didSendChanges, …
        }
    }

    public func nextRecordZoneChangeBatch(_ context: CKSyncEngine.SendChangesContext,
                                          syncEngine: CKSyncEngine) async -> CKSyncEngine.RecordZoneChangeBatch? {
        let pending = syncEngine.state.pendingRecordZoneChanges.filter { context.options.scope.contains($0) }
        guard !pending.isEmpty else { return nil }
        return await CKSyncEngine.RecordZoneChangeBatch(pendingChanges: pending) { [weak self] recordID in
            guard let self, let id = UUID(uuidString: recordID.recordName),
                  let r = self.store.outgoingRecord(id: id) else {
                syncEngine.state.remove(pendingRecordZoneChanges: [.saveRecord(recordID)])
                return nil
            }
            return self.makeCKRecord(r)
        }
    }
}
#endif
