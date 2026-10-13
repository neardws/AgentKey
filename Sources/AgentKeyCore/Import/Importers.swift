import Foundation

/// Supported import sources.
public enum ImportFormat: String, CaseIterable, Codable, Sendable {
    case onePassword1PUX = "1pux"
    case onePasswordCSV = "1password-csv"
    case applePasswordsCSV = "apple-csv"
    case chromeCSV = "chrome-csv"          // also Edge / Brave / Arc / Opera (same columns)
    case firefoxCSV = "firefox-csv"
    case bitwardenJSON = "bitwarden-json"
    case bitwardenCSV = "bitwarden-csv"
    case genericCSV = "csv"
}

public struct ImportSkip: Codable, Equatable, Sendable {
    public var index: Int            // 1-based row / item index in the source
    public var title: String?
    public var reason: String
}

public struct ImportReport: Codable, Sendable {
    public var format: ImportFormat
    public var totalInSource = 0
    public var imported = 0
    public var byKind: [String: Int] = [:]
    public var withTOTP = 0
    public var duplicatesInSource = 0
    public var duplicatesOfExisting = 0
    public var skipped: [ImportSkip] = []
    public var warnings: [String] = []
    public var dryRun = false
    public init(format: ImportFormat) { self.format = format }
}

public struct ImportResult: Sendable {
    public var items: [VaultItem]
    public var report: ImportReport
}

public enum ImportError: Error, CustomStringConvertible {
    case unrecognized(String), invalid(String)
    public var description: String {
        switch self {
        case .unrecognized(let s): return "could not detect import format: \(s)"
        case .invalid(let s): return "invalid import file: \(s)"
        }
    }
}

/// Column mapping for generic CSV: our field → source header (case-insensitive).
public struct CSVColumnMap: Sendable, Equatable {
    public var title, url, username, password, notes, totp, tags: String?
    public init(title: String? = nil, url: String? = nil, username: String? = nil, password: String? = nil,
                notes: String? = nil, totp: String? = nil, tags: String? = nil) {
        self.title = title; self.url = url; self.username = username; self.password = password
        self.notes = notes; self.totp = totp; self.tags = tags
    }
    /// Parse "title=Name,url=Website,..."
    public init(spec: String) throws {
        self.init()
        for pair in spec.split(separator: ",") {
            let kv = pair.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard kv.count == 2 else { throw ImportError.invalid("bad --map entry '\(pair)'") }
            switch kv[0].lowercased() {
            case "title", "name": title = kv[1]
            case "url", "website": url = kv[1]
            case "username", "user", "login": username = kv[1]
            case "password": password = kv[1]
            case "notes", "note": notes = kv[1]
            case "totp", "otp": totp = kv[1]
            case "tags", "folder": tags = kv[1]
            default: throw ImportError.invalid("unknown --map key '\(kv[0])'")
            }
        }
    }

    static let synonyms: [WritableKeyPath<CSVColumnMap, String?>: [String]] = [
        \.title: ["title", "name", "item name", "account", "site", "service"],
        \.url: ["url", "uri", "website", "web site", "login_uri", "login uri", "address", "hostname", "origin"],
        \.username: ["username", "user name", "login", "login_username", "email", "e-mail", "user", "account name"],
        \.password: ["password", "login_password", "pass", "pwd"],
        \.notes: ["notes", "note", "comments", "comment", "extra"],
        \.totp: ["otpauth", "totp", "otp", "login_totp", "one-time password", "2fa", "authenticator"],
        \.tags: ["tags", "tag", "folder", "group", "grouping", "category", "labels"],
    ]

    /// Fill unset columns by matching known header names.
    func resolved(header: [String]) -> CSVColumnMap {
        var m = self
        for (kp, names) in Self.synonyms where m[keyPath: kp] == nil {
            m[keyPath: kp] = names.first { header.contains($0) }
        }
        for kp in Self.synonyms.keys { m[keyPath: kp] = m[keyPath: kp]?.lowercased() }
        return m
    }
}

/// A source-independent login/note candidate before conversion to VaultItem.
struct Candidate {
    var title: String?
    var urls: [String] = []
    var username: String?
    var password: String?
    var notes: String?
    var totp: String?
    var tags: [String] = []
    var extraFields: [ItemField] = []
    var kind: ItemKind? = nil       // forced kind (e.g. API credential)
}

public enum Importer {
    // MARK: entry points

    public static func detect(data: Data, filename: String) throws -> ImportFormat {
        let lower = filename.lowercased()
        if lower.hasSuffix(".1pux") || (data.starts(with: [0x50, 0x4b]) && ((try? ZipArchive(data))?.entries.contains { $0.name == "export.data" } ?? false)) {
            return .onePassword1PUX
        }
        guard let text = String(data: data, encoding: .utf8) else { throw ImportError.unrecognized("not UTF-8 text") }
        let trimmed = text.drop { $0.isWhitespace || $0 == "\u{FEFF}" }
        if trimmed.first == "{" {
            if let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any], o["items"] != nil {
                if (o["encrypted"] as? Bool) == true { throw ImportError.invalid("Bitwarden export is encrypted; export as unencrypted JSON") }
                return .bitwardenJSON
            }
            throw ImportError.unrecognized("JSON file is not a Bitwarden export")
        }
        let h = Set(CSV.records(String(text.prefix(4096))).header)
        if h.isSuperset(of: ["httprealm", "formactionorigin"]) { return .firefoxCSV }
        if h.isSuperset(of: ["login_uri", "login_password"]) { return .bitwardenCSV }
        if h.isSuperset(of: ["title", "url", "username", "password", "otpauth"]) {
            return h.contains("favorite") || h.contains("archived") || h.contains("tags") ? .onePasswordCSV : .applePasswordsCSV
        }
        if h.isSuperset(of: ["name", "url", "username", "password"]) { return .chromeCSV }
        if !h.isEmpty { return .genericCSV }
        throw ImportError.unrecognized("empty file")
    }

    public static func parse(data: Data, format: ImportFormat, columnMap: CSVColumnMap = CSVColumnMap()) throws -> ImportResult {
        var report = ImportReport(format: format)
        var cands: [(Int, Candidate)] = []
        switch format {
        case .onePassword1PUX: cands = try onePUX(data, &report)
        case .bitwardenJSON: cands = try bitwardenJSON(data, &report)
        default:
            guard let text = String(data: data, encoding: .utf8) else { throw ImportError.invalid("not UTF-8") }
            cands = try csv(text, format: format, map: columnMap, &report)
        }
        var items: [VaultItem] = []
        var seen = Set<String>()
        for (idx, c) in cands {
            guard let item = convert(c, index: idx, report: &report) else { continue }
            let key = dedupeKey(item)
            if seen.contains(key) {
                report.duplicatesInSource += 1
                report.skipped.append(ImportSkip(index: idx, title: item.title, reason: "duplicate within import"))
                continue
            }
            seen.insert(key); items.append(item)
        }
        report.imported = items.count
        for i in items {
            report.byKind[i.kind.rawValue, default: 0] += 1
            if i.fields.contains(where: { $0.id == "totp" }) { report.withTOTP += 1 }
        }
        return ImportResult(items: items, report: report)
    }

    /// Remove items already present in the vault (same dedupe key); updates the report.
    public static func dropExisting(_ r: inout ImportResult, existing: [VaultItem]) {
        let keys = Set(existing.map(dedupeKey))
        var kept: [VaultItem] = []
        for i in r.items {
            if keys.contains(dedupeKey(i)) {
                r.report.duplicatesOfExisting += 1
                r.report.skipped.append(ImportSkip(index: 0, title: i.title, reason: "already in vault"))
                r.report.byKind[i.kind.rawValue, default: 1] -= 1
                if i.fields.contains(where: { $0.id == "totp" }) { r.report.withTOTP -= 1 }
            } else { kept.append(i) }
        }
        r.items = kept
        r.report.imported = kept.count
    }

    // MARK: dedupe

    /// Logins: host + username + password (+ totp). Notes/others: kind + title + primary value.
    public static func dedupeKey(_ i: VaultItem) -> String {
        let v = { (id: String) in i.fields.first { $0.id == id }?.value ?? "" }
        let digest = { (s: String) in Data(SHA256.hash(data: Data(s.utf8))).hex }   // keep plaintext out of the key
        switch i.kind {
        case .login:
            let host = i.urls.first.flatMap(normalizedHost) ?? i.title.lowercased()
            return "login|\(host)|\((i.username ?? "").lowercased())|" + digest(v("password") + "\u{0}" + v("totp"))
        default:
            return "\(i.kind.rawValue)|\(i.title.lowercased())|" + digest(i.fields.map(\.value).joined(separator: "\u{0}"))
        }
    }

    static func normalizedHost(_ s: String) -> String? {
        let withScheme = s.contains("://") ? s : "https://" + s
        guard var h = URLComponents(string: withScheme)?.host?.lowercased(), !h.isEmpty else { return nil }
        if h.hasPrefix("www.") { h.removeFirst(4) }
        return h
    }

    // MARK: conversion

    static func clean(_ s: String?) -> String? {
        guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
        return t
    }

    static func convert(_ c: Candidate, index: Int, report: inout ImportReport) -> VaultItem? {
        let urls = c.urls.compactMap(clean)
        let user = clean(c.username), pass = c.password.flatMap { $0.isEmpty ? nil : $0 }
        let notes = clean(c.notes)
        var totp: String? = nil
        if let raw = clean(c.totp) {
            totp = OTPAuthURI.normalize(raw, issuer: clean(c.title), account: user)
            if totp == nil { report.warnings.append("row \(index): unsupported TOTP value ignored (not otpauth:// or Base32)") }
        }
        let title = clean(c.title) ?? urls.first.flatMap(normalizedHost) ?? user
        guard let title else {
            report.skipped.append(ImportSkip(index: index, title: nil, reason: "no title, URL or username"))
            return nil
        }
        var item: VaultItem
        if c.kind == .apiToken, let pass {
            item = .apiToken(title: title, token: pass)
            if let user { item.fields.insert(ItemField(id: "username", value: user, concealed: false), at: 0); item.username = user }
        } else if pass != nil || user != nil || !urls.isEmpty || (totp != nil && c.kind != .secureNote) {
            if pass == nil && user == nil && totp == nil {
                report.skipped.append(ImportSkip(index: index, title: title, reason: "URL only, no credentials")); return nil
            }
            if pass == nil && user == nil, let totp {
                item = .totp(title: title, secretOrURI: totp)
            } else {
                item = .login(title: title, username: user ?? "", password: pass ?? "", url: urls.first)
                if user == nil { item.username = nil; item.fields.removeAll { $0.id == "username" } }
                if pass == nil { item.fields.removeAll { $0.id == "password" } }
                item.urls = urls
                if let totp { item.fields.append(ItemField(id: "totp", label: "one-time password", value: totp)) }
            }
        } else if let notes {
            item = .secureNote(title: title, text: notes)
        } else {
            report.skipped.append(ImportSkip(index: index, title: title, reason: "empty item")); return nil
        }
        if item.kind != .secureNote { item.notes = notes }
        item.tags = Array(Set(c.tags.compactMap(clean))).sorted()
        item.fields += c.extraFields.filter { f in !item.fields.contains { $0.id == f.id } }
        // Imported logins are human-first: agents get nothing until the user enables modes.
        item.agentModes = []
        return item
    }

    // MARK: CSV formats

    static func csv(_ text: String, format: ImportFormat, map: CSVColumnMap, _ report: inout ImportReport) throws -> [(Int, Candidate)] {
        let (header, rows) = CSV.records(text)
        guard !header.isEmpty else { throw ImportError.invalid("no CSV header") }
        report.totalInSource = rows.count
        let m: CSVColumnMap
        switch format {
        case .onePasswordCSV: m = CSVColumnMap(title: "title", url: "url", username: "username", password: "password", notes: "notes", totp: "otpauth", tags: "tags")
        case .applePasswordsCSV: m = CSVColumnMap(title: "title", url: "url", username: "username", password: "password", notes: "notes", totp: "otpauth")
        case .chromeCSV: m = CSVColumnMap(title: "name", url: "url", username: "username", password: "password", notes: "note")
        case .firefoxCSV: m = CSVColumnMap(url: "url", username: "username", password: "password")
        case .bitwardenCSV: m = CSVColumnMap(title: "name", url: "login_uri", username: "login_username", password: "login_password", notes: "notes", totp: "login_totp", tags: "folder")
        default: m = map.resolved(header: header)
        }
        if format == .genericCSV && m.password == nil && m.notes == nil {
            throw ImportError.invalid("could not find a password or notes column; pass --map password=<column>,...")
        }
        var out: [(Int, Candidate)] = []
        for (i, r) in rows.enumerated() {
            let get = { (k: String?) in k.flatMap { r[$0] } }
            var c = Candidate()
            c.title = get(m.title); c.username = get(m.username); c.password = get(m.password)
            c.notes = get(m.notes); c.totp = get(m.totp)
            if let u = get(m.url) {
                // Bitwarden CSV can hold several URIs separated by commas/newlines
                c.urls = u.split(whereSeparator: { $0 == "\n" || (format == .bitwardenCSV && $0 == ",") }).map(String.init)
            }
            if let t = get(m.tags) {
                c.tags = t.split(whereSeparator: { $0 == "," || $0 == ";" }).map { String($0).trimmingCharacters(in: .whitespaces) }
            }
            if format == .firefoxCSV, let u = c.urls.first {
                if u.hasPrefix("chrome://") { report.skipped.append(ImportSkip(index: i + 1, title: u, reason: "Firefox internal entry")); continue }
                c.title = normalizedHost(u)
            }
            if format == .bitwardenCSV, let t = r["type"], t != "login", t != "note", !t.isEmpty {
                report.skipped.append(ImportSkip(index: i + 1, title: c.title, reason: "unsupported Bitwarden type '\(t)'")); continue
            }
            if format == .bitwardenCSV, r["type"] == "note" { c.kind = .secureNote }
            if format == .onePasswordCSV, r["archived"] == "true" || r["archived"] == "1" { c.tags.append("archived") }
            out.append((i + 1, c))
        }
        return out
    }

    // MARK: Bitwarden JSON

    static func bitwardenJSON(_ data: Data, _ report: inout ImportReport) throws -> [(Int, Candidate)] {
        guard let o = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ImportError.invalid("not a JSON object") }
        if (o["encrypted"] as? Bool) == true { throw ImportError.invalid("Bitwarden export is encrypted; export as unencrypted JSON") }
        let folders = Dictionary(((o["folders"] as? [[String: Any]]) ?? []).compactMap { f -> (String, String)? in
            guard let id = f["id"] as? String, let n = f["name"] as? String else { return nil }; return (id, n)
        }, uniquingKeysWith: { a, _ in a })
        let items = (o["items"] as? [[String: Any]]) ?? []
        report.totalInSource = items.count
        var out: [(Int, Candidate)] = []
        for (i, it) in items.enumerated() {
            let type = it["type"] as? Int ?? 0
            var c = Candidate()
            c.title = it["name"] as? String
            c.notes = it["notes"] as? String
            if let f = it["folderId"] as? String, let n = folders[f] { c.tags = [n] }
            for f in (it["fields"] as? [[String: Any]]) ?? [] {
                guard let n = f["name"] as? String, let v = f["value"] as? String, !v.isEmpty else { continue }
                let id = "custom." + n.lowercased().replacingOccurrences(of: " ", with: "_")
                c.extraFields.append(ItemField(id: id, label: n, value: v, concealed: (f["type"] as? Int) == 1))
            }
            switch type {
            case 1:
                let l = it["login"] as? [String: Any] ?? [:]
                c.username = l["username"] as? String; c.password = l["password"] as? String; c.totp = l["totp"] as? String
                c.urls = ((l["uris"] as? [[String: Any]]) ?? []).compactMap { $0["uri"] as? String }
                if !((l["fido2Credentials"] as? [Any]) ?? []).isEmpty {
                    report.warnings.append("item \(i + 1) '\(c.title ?? "")': passkey not imported (passkeys are not exportable)")
                }
            case 2: c.kind = .secureNote
            case 3, 4, 5:
                report.skipped.append(ImportSkip(index: i + 1, title: c.title, reason: ["", "", "", "card", "identity", "SSH key"][type] + " items not supported yet"))
                continue
            default:
                report.skipped.append(ImportSkip(index: i + 1, title: c.title, reason: "unknown Bitwarden type \(type)")); continue
            }
            out.append((i + 1, c))
        }
        return out
    }

    // MARK: 1Password .1pux

    static func onePUX(_ data: Data, _ report: inout ImportReport) throws -> [(Int, Candidate)] {
        let zip = try ZipArchive(data)
        guard let json = try zip.read("export.data") else { throw ImportError.invalid(".1pux has no export.data") }
        guard let root = try JSONSerialization.jsonObject(with: json) as? [String: Any] else { throw ImportError.invalid("export.data is not JSON") }
        if zip.entries.contains(where: { $0.name.hasPrefix("files/") }) {
            report.warnings.append("file attachments in the .1pux were not imported")
        }
        var out: [(Int, Candidate)] = []
        var idx = 0
        for acct in (root["accounts"] as? [[String: Any]]) ?? [] {
            for vault in (acct["vaults"] as? [[String: Any]]) ?? [] {
                let vaultName = (vault["attrs"] as? [String: Any])?["name"] as? String
                for it in (vault["items"] as? [[String: Any]]) ?? [] {
                    idx += 1
                    let ov = it["overview"] as? [String: Any] ?? [:]
                    let det = it["details"] as? [String: Any] ?? [:]
                    let title = ov["title"] as? String
                    if (it["state"] as? String) == "deleted" || (it["trashed"] as? Bool) == true {
                        report.skipped.append(ImportSkip(index: idx, title: title, reason: "in 1Password trash")); continue
                    }
                    var c = Candidate()
                    c.title = title
                    c.urls = ((ov["urls"] as? [[String: Any]]) ?? []).compactMap { $0["url"] as? String }
                    if c.urls.isEmpty, let u = ov["url"] as? String { c.urls = [u] }
                    c.tags = (ov["tags"] as? [String]) ?? []
                    if let v = vaultName, v != "Personal" && v != "Private" { c.tags.append(v) }
                    if (it["state"] as? String) == "archived" { c.tags.append("archived") }
                    c.notes = det["notesPlain"] as? String
                    for f in (det["loginFields"] as? [[String: Any]]) ?? [] {
                        let v = f["value"] as? String
                        switch f["designation"] as? String {
                        case "username": c.username = v
                        case "password": c.password = v
                        default: break
                        }
                    }
                    if c.password == nil, let p = det["password"] as? String { c.password = p }
                    // sections: TOTP, extra concealed / string fields
                    for sec in (det["sections"] as? [[String: Any]]) ?? [] {
                        for f in (sec["fields"] as? [[String: Any]]) ?? [] {
                            guard let val = f["value"] as? [String: Any], let (k, anyV) = val.first else { continue }
                            let label = (f["title"] as? String) ?? (f["id"] as? String) ?? k
                            switch k {
                            case "totp": if c.totp == nil, let s = anyV as? String { c.totp = s }
                            case "concealed", "string", "url", "email":
                                let s = (anyV as? String) ?? ((anyV as? [String: Any])?["email_address"] as? String)
                                guard let s, !s.isEmpty else { continue }
                                let fid = (f["id"] as? String) ?? label
                                if (fid == "credential" || label.lowercased() == "credential") && c.password == nil {
                                    c.password = s; continue   // API Credential item
                                }
                                if fid == "username" && c.username == nil { c.username = s; continue }
                                c.extraFields.append(ItemField(id: "custom." + fid.lowercased().replacingOccurrences(of: " ", with: "_"),
                                                               label: label, value: s, concealed: k == "concealed"))
                            default:
                                break
                            }
                        }
                    }
                    if !((det["passkey"] as? [String: Any]) ?? [:]).isEmpty {
                        report.warnings.append("item \(idx) '\(title ?? "")': passkey not imported (passkeys are not exportable)")
                    }
                    switch it["categoryUuid"] as? String {
                    case "001", "005": break                   // Login, Password
                    case "003": c.kind = .secureNote
                    case "112": c.kind = .apiToken              // API Credential
                    case let other:
                        if c.password == nil && c.username == nil && c.totp == nil && c.notes == nil && c.extraFields.isEmpty {
                            report.skipped.append(ImportSkip(index: idx, title: title, reason: "unsupported 1Password category \(other ?? "?")")); continue
                        }
                        if c.password == nil && c.username == nil && c.totp == nil {
                            c.kind = .secureNote
                            let extra = c.extraFields.map { "\($0.label): \($0.value)" }.joined(separator: "\n")
                            c.notes = [c.notes, extra].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: "\n\n")
                            c.extraFields = []
                            report.warnings.append("item \(idx) '\(title ?? "")': category \(other ?? "?") imported as secure note")
                        }
                    }
                    out.append((idx, c))
                }
            }
        }
        report.totalInSource = idx
        return out
    }
}
