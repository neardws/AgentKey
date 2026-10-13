import Foundation

/// Contract between the local encrypted store and a transport (CloudKit). Implemented by the
/// SQLite record store (Phase 2) and by test doubles. Everything crossing it is ciphertext.
public protocol SyncRecordStore: AnyObject {
    /// Opaque CKSyncEngine state (change tokens, pending changes) — persisted by the store.
    func loadEngineState() -> Data?
    func saveEngineState(_ data: Data)
    /// Current local record for upload (nil if it vanished meanwhile).
    func outgoingRecord(id: UUID) -> SyncRecord?
    /// Remote record fetched or returned in a conflict → 3-way merge into local state.
    /// Returns true if the merge produced a new local version that must be uploaded.
    func applyRemote(_ record: SyncRecord) -> Bool
    /// Remote deletion of a record (zone-level delete or purge).
    func applyRemoteDeletion(id: UUID)
    /// Upload acknowledged: becomes the new merge base.
    func didSave(_ record: SyncRecord)
    /// CKRecord system fields (change tag etc.), archived by the adapter; stored opaque.
    func systemFields(id: UUID) -> Data?
    func setSystemFields(_ data: Data?, id: UUID)
    /// Account switched / signed out: wipe synced state (keep local vault, stop syncing).
    func resetSyncState()
}
