import Foundation

/// RFC 4180 CSV parser: quoted fields, escaped quotes, embedded newlines, CRLF/LF, UTF-8 BOM,
/// and an optional delimiter (`,` default; `;` or tab for some locales).
public enum CSV {
    public static func parse(_ text: String, delimiter: Character = ",") -> [[String]] {
        var rows: [[String]] = []
        var row: [String] = []
        var field = ""
        var inQuotes = false
        var chars = Array(text)
        if chars.first == "\u{FEFF}" { chars.removeFirst() }
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if inQuotes {
                if c == "\"" {
                    if i + 1 < chars.count && chars[i + 1] == "\"" { field.append("\""); i += 1 }
                    else { inQuotes = false }
                } else { field.append(c) }
            } else {
                switch c {
                case "\"" where field.isEmpty: inQuotes = true
                case delimiter: row.append(field); field = ""
                case "\r\n", "\n", "\r":   // Swift treats CRLF as one Character
                    row.append(field); field = ""
                    if !(row.count == 1 && row[0].isEmpty) { rows.append(row) }
                    row = []
                default: field.append(c)
                }
            }
            i += 1
        }
        if !field.isEmpty || !row.isEmpty { row.append(field); rows.append(row) }
        return rows
    }

    /// Header row + records as dictionaries keyed by lower-cased, trimmed header.
    public static func records(_ text: String) -> (header: [String], rows: [[String: String]]) {
        let delim: Character = {
            let first = text.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
            let counts: [(Character, Int)] = [(",", first.filter { $0 == "," }.count),
                                              (";", first.filter { $0 == ";" }.count),
                                              ("\t", first.filter { $0 == "\t" }.count)]
            return counts.max { $0.1 < $1.1 }.map { $0.1 > 0 ? $0.0 : "," } ?? ","
        }()
        let all = parse(text, delimiter: delim)
        guard let h = all.first else { return ([], []) }
        let header = h.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        let rows = all.dropFirst().map { r -> [String: String] in
            var d: [String: String] = [:]
            for (i, k) in header.enumerated() where i < r.count && !k.isEmpty { d[k] = r[i] }
            return d
        }
        return (header, Array(rows))
    }
}
