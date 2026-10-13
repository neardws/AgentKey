import Foundation

public enum ItemKind: String, Codable, CaseIterable, Sendable {
    case login, secureNote = "secure_note", apiToken = "api_token", totp
}

public struct ItemField: Codable, Equatable, Sendable {
    public var id: String          // stable id used in refs, e.g. "password", "token"
    public var label: String
    public var value: String
    public var concealed: Bool
    public init(id: String, label: String? = nil, value: String, concealed: Bool = true) {
        self.id = id; self.label = label ?? id; self.value = value; self.concealed = concealed
    }
}

public struct VaultItem: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var kind: ItemKind
    public var title: String
    public var username: String?
    public var urls: [String]
    public var notes: String?
    public var fields: [ItemField]
    public var tags: [String]
    /// Release modes agents may use for this item. `reveal` is never on by default.
    public var agentModes: [ReleaseMode]
    /// For `http` mode (roadmap): hosts the secret may be sent to.
    public var allowedHosts: [String]
    public var createdAt: Date
    public var updatedAt: Date
    // Lifecycle / hygiene metadata (optional so older vault files still decode)
    public var lastUsedAt: Date?          // last AutoFill / agent release
    public var passwordChangedAt: Date?   // last time the primary secret changed
    public var archivedAt: Date?
    public var trashedAt: Date?           // soft delete; purge after retention
    public var history: [ItemHistoryEntry]?

    public var isTrashed: Bool { trashedAt != nil }
    public var isArchived: Bool { archivedAt != nil }

    /// Record a previous value before changing a field (kept encrypted inside the item).
    public mutating func recordHistory(_ reason: String, fields old: [ItemField]) {
        var h = history ?? []
        h.append(ItemHistoryEntry(at: Date(), reason: reason, fields: old))
        history = Array(h.suffix(20))
    }

    public init(id: UUID = UUID(), kind: ItemKind, title: String, username: String? = nil,
                urls: [String] = [], notes: String? = nil, fields: [ItemField] = [], tags: [String] = [],
                agentModes: [ReleaseMode] = [.run, .totp], allowedHosts: [String] = [],
                createdAt: Date = Date(), updatedAt: Date = Date()) {
        self.id = id; self.kind = kind; self.title = title; self.username = username
        self.urls = urls; self.notes = notes; self.fields = fields; self.tags = tags
        self.agentModes = agentModes; self.allowedHosts = allowedHosts
        self.createdAt = createdAt; self.updatedAt = updatedAt
    }

    /// Default field for refs that omit one.
    public var primaryFieldID: String? {
        switch kind {
        case .login: return "password"
        case .apiToken: return "token"
        case .totp: return "totp"
        case .secureNote: return "note"
        }
    }

    public func field(_ id: String?) -> ItemField? {
        let fid = id ?? primaryFieldID
        return fields.first { $0.id == fid }
    }

    /// Metadata that is safe to show to agents (no values).
    public var overview: ItemOverview {
        ItemOverview(id: id, ref: ItemRef.make(title: title), kind: kind, title: title,
                     username: username, urls: urls, tags: tags,
                     fields: fields.map { .init(id: $0.id, label: $0.label, concealed: $0.concealed) },
                     agentModes: agentModes)
    }

    public static func login(title: String, username: String, password: String, url: String? = nil) -> VaultItem {
        VaultItem(kind: .login, title: title, username: username, urls: url.map { [$0] } ?? [],
                  fields: [ItemField(id: "username", value: username, concealed: false),
                           ItemField(id: "password", value: password)])
    }
    public static func apiToken(title: String, token: String) -> VaultItem {
        VaultItem(kind: .apiToken, title: title, fields: [ItemField(id: "token", value: token)])
    }
    public static func secureNote(title: String, text: String) -> VaultItem {
        VaultItem(kind: .secureNote, title: title, fields: [ItemField(id: "note", value: text)], agentModes: [])
    }
    public static func totp(title: String, secretOrURI: String) -> VaultItem {
        VaultItem(kind: .totp, title: title, fields: [ItemField(id: "totp", value: secretOrURI)], agentModes: [.totp])
    }
}

public struct ItemHistoryEntry: Codable, Equatable, Sendable {
    public var at: Date
    public var reason: String
    public var fields: [ItemField]
}

public struct ItemOverview: Codable, Equatable, Sendable {
    public struct FieldInfo: Codable, Equatable, Sendable { public var id, label: String; public var concealed: Bool }
    public var id: UUID
    public var ref: String
    public var kind: ItemKind
    public var title: String
    public var username: String?
    public var urls: [String]
    public var tags: [String]
    public var fields: [FieldInfo]
    public var agentModes: [ReleaseMode]
}

/// How plaintext leaves the vault. See docs/DESIGN.zh.md §12.1.
public enum ReleaseMode: String, Codable, CaseIterable, Sendable {
    case run      // injected into a child process env (`agentkey exec`)
    case totp     // only the current 6–8 digit code
    case inject   // render template to 0600 temp file (roadmap)
    case http     // daemon performs the HTTPS call (roadmap)
    case fill     // system AutoFill (roadmap)
    case reveal   // raw plaintext to caller — OFF by default
}

/// Reference syntax: `ak://<item-title-or-uuid>[/<field-id>]`
public struct ItemRef: Equatable, Sendable, CustomStringConvertible {
    public var item: String
    public var field: String?
    public init(item: String, field: String? = nil) { self.item = item; self.field = field }

    public init?(_ s: String) {
        var body = s
        if body.hasPrefix("ak://") { body.removeFirst(5) }
        let parts = body.split(separator: "/", maxSplits: 1).map(String.init)
        guard let first = parts.first, !first.isEmpty else { return nil }
        item = first.removingPercentEncoding ?? first
        field = parts.count > 1 && !parts[1].isEmpty ? parts[1] : nil
    }

    public static func make(title: String, field: String? = nil) -> String {
        let t = title.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? title
        return "ak://\(t)" + (field.map { "/\($0)" } ?? "")
    }
    public var description: String { ItemRef.make(title: item, field: field) }
}
