import Foundation

/// Minimal in-memory ZIP reader (stored + deflate), enough for 1Password `.1pux`.
/// Entries are never written to disk.
public enum ZipError: Error, CustomStringConvertible {
    case notZip, unsupported(String), corrupt(String), tooLarge
    public var description: String {
        switch self {
        case .notZip: return "not a ZIP archive"
        case .unsupported(let s): return "unsupported ZIP feature: \(s)"
        case .corrupt(let s): return "corrupt ZIP: \(s)"
        case .tooLarge: return "ZIP entry too large"
        }
    }
}

public struct ZipArchive {
    public struct Entry { public let name: String; let method: UInt16; let compSize: Int; let size: Int; let localOffset: Int; let flags: UInt16; let crc: UInt32 }
    let data: [UInt8]
    public let entries: [Entry]
    public static let maxEntrySize = 512 << 20

    public init(_ d: Data) throws {
        data = [UInt8](d)
        guard data.count >= 22, data[0] == 0x50, data[1] == 0x4b else { throw ZipError.notZip }
        // find End Of Central Directory
        var eocd = -1
        var i = data.count - 22
        while i >= max(0, data.count - 22 - 65_535) {
            if data[i] == 0x50 && data[i+1] == 0x4b && data[i+2] == 0x05 && data[i+3] == 0x06 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw ZipError.corrupt("no end of central directory") }
        let count = Int(Self.u16(data, eocd + 10))
        var p = Int(Self.u32(data, eocd + 16))
        if count == 0xffff || p == 0xffff_ffff { throw ZipError.unsupported("zip64") }
        var es: [Entry] = []
        for _ in 0..<count {
            guard p + 46 <= data.count, Self.u32(data, p) == 0x02014b50 else { throw ZipError.corrupt("bad central header") }
            let flags = Self.u16(data, p + 8), method = Self.u16(data, p + 10)
            let crc = Self.u32(data, p + 16)
            let comp = Int(Self.u32(data, p + 20)), size = Int(Self.u32(data, p + 24))
            let nl = Int(Self.u16(data, p + 28)), xl = Int(Self.u16(data, p + 30)), cl = Int(Self.u16(data, p + 32))
            let off = Int(Self.u32(data, p + 42))
            guard p + 46 + nl <= data.count else { throw ZipError.corrupt("name") }
            let name = String(decoding: data[(p + 46)..<(p + 46 + nl)], as: UTF8.self)
            es.append(Entry(name: name, method: method, compSize: comp, size: size, localOffset: off, flags: flags, crc: crc))
            p += 46 + nl + xl + cl
        }
        entries = es
    }

    public func read(_ name: String) throws -> Data? {
        guard let e = entries.first(where: { $0.name == name }) else { return nil }
        if e.flags & 1 != 0 { throw ZipError.unsupported("encrypted entry") }
        guard e.size <= Self.maxEntrySize else { throw ZipError.tooLarge }
        let lh = e.localOffset
        guard lh + 30 <= data.count, Self.u32(data, lh) == 0x04034b50 else { throw ZipError.corrupt("bad local header") }
        let start = lh + 30 + Int(Self.u16(data, lh + 26)) + Int(Self.u16(data, lh + 28))
        guard start + e.compSize <= data.count else { throw ZipError.corrupt("truncated") }
        let comp = Array(data[start..<(start + e.compSize)])
        let out: [UInt8]
        switch e.method {
        case 0: out = comp
        case 8: out = try Inflate.inflate(comp, expectedSize: e.size)
        default: throw ZipError.unsupported("compression method \(e.method)")
        }
        guard out.count == e.size else { throw ZipError.corrupt("size mismatch") }
        guard CRC32.checksum(out) == e.crc else { throw ZipError.corrupt("CRC mismatch for \(name)") }
        return Data(out)
    }

    static func u16(_ d: [UInt8], _ i: Int) -> UInt16 { UInt16(d[i]) | UInt16(d[i+1]) << 8 }
    static func u32(_ d: [UInt8], _ i: Int) -> UInt32 { UInt32(d[i]) | UInt32(d[i+1]) << 8 | UInt32(d[i+2]) << 16 | UInt32(d[i+3]) << 24 }
}

enum CRC32 {
    static let table: [UInt32] = (0..<256).map { n -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1 }
        return c
    }
    static func checksum(_ b: [UInt8]) -> UInt32 {
        var c: UInt32 = 0xffff_ffff
        for x in b { c = table[Int((c ^ UInt32(x)) & 0xff)] ^ (c >> 8) }
        return c ^ 0xffff_ffff
    }
}

/// Pure-Swift RFC 1951 inflate (raw deflate), used on all platforms so behaviour is identical.
enum Inflate {
    struct Bits {
        let d: [UInt8]; var pos = 0; var bit = 0
        mutating func get(_ n: Int) throws -> Int {
            var v = 0
            for k in 0..<n {
                guard pos < d.count else { throw ZipError.corrupt("deflate: out of input") }
                v |= Int((d[pos] >> UInt8(bit)) & 1) << k
                bit += 1; if bit == 8 { bit = 0; pos += 1 }
            }
            return v
        }
        mutating func align() { if bit != 0 { bit = 0; pos += 1 } }
    }

    struct Huffman {
        var counts = [Int](repeating: 0, count: 16)
        var symbols: [Int] = []
        init(lengths: [Int]) {
            for l in lengths { counts[l] += 1 }
            counts[0] = 0
            var offs = [Int](repeating: 0, count: 16)
            for i in 1..<16 { offs[i] = offs[i-1] + counts[i-1] }
            symbols = [Int](repeating: 0, count: lengths.count)
            for (s, l) in lengths.enumerated() where l != 0 { symbols[offs[l]] = s; offs[l] += 1 }
        }
        func decode(_ b: inout Bits) throws -> Int {
            var code = 0, first = 0, index = 0
            for len in 1..<16 {
                code |= try b.get(1)
                let c = counts[len]
                if code - c < first { return symbols[index + (code - first)] }
                index += c; first += c; first <<= 1; code <<= 1
            }
            throw ZipError.corrupt("deflate: bad code")
        }
    }

    static let lbase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
    static let lext  = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
    static let dbase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
    static let dext  = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]
    static let fixedL = Huffman(lengths: (0..<288).map { $0 < 144 ? 8 : $0 < 256 ? 9 : $0 < 280 ? 7 : 8 })
    static let fixedD = Huffman(lengths: [Int](repeating: 5, count: 30))

    static func inflate(_ input: [UInt8], expectedSize: Int) throws -> [UInt8] {
        var b = Bits(d: input)
        var out: [UInt8] = []; out.reserveCapacity(expectedSize)
        var final = 0
        repeat {
            final = try b.get(1)
            let type = try b.get(2)
            switch type {
            case 0:
                b.align()
                guard b.pos + 4 <= input.count else { throw ZipError.corrupt("deflate: stored header") }
                let len = Int(input[b.pos]) | Int(input[b.pos+1]) << 8
                b.pos += 4
                guard b.pos + len <= input.count else { throw ZipError.corrupt("deflate: stored data") }
                out.append(contentsOf: input[b.pos..<(b.pos + len)]); b.pos += len
            case 1: try block(&b, &out, fixedL, fixedD)
            case 2:
                let hlit = try b.get(5) + 257, hdist = try b.get(5) + 1, hclen = try b.get(4) + 4
                let order = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
                var cl = [Int](repeating: 0, count: 19)
                for i in 0..<hclen { cl[order[i]] = try b.get(3) }
                let ch = Huffman(lengths: cl)
                var lens: [Int] = []
                while lens.count < hlit + hdist {
                    let sym = try ch.decode(&b)
                    switch sym {
                    case 0..<16: lens.append(sym)
                    case 16:
                        guard let prev = lens.last else { throw ZipError.corrupt("deflate: repeat") }
                        lens += [Int](repeating: prev, count: 3 + (try b.get(2)))
                    case 17: lens += [Int](repeating: 0, count: 3 + (try b.get(3)))
                    default: lens += [Int](repeating: 0, count: 11 + (try b.get(7)))
                    }
                }
                guard lens.count == hlit + hdist else { throw ZipError.corrupt("deflate: lengths") }
                try block(&b, &out, Huffman(lengths: Array(lens[0..<hlit])), Huffman(lengths: Array(lens[hlit...])))
            default: throw ZipError.corrupt("deflate: block type 3")
            }
            if out.count > ZipArchive.maxEntrySize { throw ZipError.tooLarge }
        } while final == 0
        return out
    }

    static func block(_ b: inout Bits, _ out: inout [UInt8], _ l: Huffman, _ d: Huffman) throws {
        while true {
            let sym = try l.decode(&b)
            if sym < 256 { out.append(UInt8(sym)); continue }
            if sym == 256 { return }
            let li = sym - 257
            guard li < 29 else { throw ZipError.corrupt("deflate: length symbol") }
            let len = lbase[li] + (try b.get(lext[li]))
            let di = try d.decode(&b)
            guard di < 30 else { throw ZipError.corrupt("deflate: dist symbol") }
            let dist = dbase[di] + (try b.get(dext[di]))
            guard dist <= out.count else { throw ZipError.corrupt("deflate: distance too far") }
            let start = out.count - dist
            for k in 0..<len { out.append(out[start + k]) }
            if out.count > ZipArchive.maxEntrySize { throw ZipError.tooLarge }
        }
    }
}
