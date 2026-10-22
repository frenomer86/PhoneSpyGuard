import Foundation

/// One file inside a tar archive.
public struct TarEntry: Sendable {
    public let path: String
    public let size: Int64
    public let isFile: Bool
    public let modified: Date?
}

/// A forward-only tar reader (ustar, GNU long names, pax paths) over a byte
/// stream. It never seeks and never holds more than the entry the caller asks
/// for, so a sysdiagnose archive is read in one pass straight out of gzip.
public final class TarReader {
    private let stream: ByteStream
    private var buffer: [UInt8] = []
    private var bufPos = 0
    /// Bytes of the current entry's data (plus padding) not yet consumed.
    private var pendingSkip: Int64 = 0
    private var pendingData: Int64 = 0

    public init(stream: ByteStream) {
        self.stream = stream
    }

    private func readExactly(_ n: Int) throws -> [UInt8]? {
        var out = [UInt8]()
        out.reserveCapacity(n)
        while out.count < n {
            if bufPos >= buffer.count {
                buffer = try stream.read(max: max(65_536, n - out.count))
                bufPos = 0
                if buffer.isEmpty { return out.isEmpty ? nil : out }
            }
            let take = min(n - out.count, buffer.count - bufPos)
            out.append(contentsOf: buffer[bufPos..<bufPos + take])
            bufPos += take
        }
        return out
    }

    private func skip(_ n: Int64) throws {
        var left = n
        while left > 0 {
            if bufPos >= buffer.count {
                buffer = try stream.read(max: 1 << 16)
                bufPos = 0
                if buffer.isEmpty { throw ArchiveError("Archive ends inside an entry") }
            }
            let take = Int(min(left, Int64(buffer.count - bufPos)))
            bufPos += take
            left -= Int64(take)
        }
    }

    private static func padded(_ size: Int64) -> Int64 { (size + 511) / 512 * 512 }

    /// The next entry, skipping whatever of the previous one was not read.
    public func next() throws -> TarEntry? {
        try skip(pendingSkip)
        pendingSkip = 0
        pendingData = 0
        var longName: String?
        while true {
            guard let header = try readExactly(512) else { return nil }
            guard header.count == 512 else { throw ArchiveError("Archive ends inside a header") }
            if header.allSatisfy({ $0 == 0 }) { return nil }
            guard Self.checksumOK(header) else { throw ArchiveError("Not a tar archive (bad header checksum)") }

            let size = try Self.number(header[124..<136])
            let type = header[156]
            let body = Self.padded(size)
            switch type {
            case UInt8(ascii: "L"): // GNU long name for the next entry
                guard size < 65_536, let data = try readExactly(Int(body)) else { throw ArchiveError("Bad long name") }
                longName = Self.cString(data[0..<Int(size)])
                continue
            case UInt8(ascii: "x"): // pax extended header
                guard size < 1 << 20, let data = try readExactly(Int(body)) else { throw ArchiveError("Bad pax header") }
                if let p = Self.paxPath(Array(data[0..<Int(size)])) { longName = p }
                continue
            case UInt8(ascii: "g"), UInt8(ascii: "K"):
                try skip(body)
                continue
            default:
                break
            }
            var name = Self.cString(header[0..<100])
            let isUstar = Self.cString(header[257..<262]) == "ustar"
            if isUstar {
                let prefix = Self.cString(header[345..<500])
                if !prefix.isEmpty { name = prefix + "/" + name }
            }
            if let l = longName { name = l }
            let isFile = type == 0 || type == UInt8(ascii: "0") || type == UInt8(ascii: "7")
            let mtime = (try? Self.number(header[136..<148])).map { Date(timeIntervalSince1970: TimeInterval($0)) }
            pendingData = isFile ? size : 0
            pendingSkip = isFile ? body : (type == UInt8(ascii: "5") ? 0 : body)
            return TarEntry(path: name, size: isFile ? size : 0, isFile: isFile, modified: mtime)
        }
    }

    /// Read up to `limit` bytes of the current entry's data. The rest is
    /// skipped on the next `next()`.
    public func readData(limit: Int) throws -> Data {
        let n = Int(min(Int64(limit), pendingData))
        guard n > 0 else { return Data() }
        guard let bytes = try readExactly(n), bytes.count == n else { throw ArchiveError("Archive ends inside an entry") }
        pendingData -= Int64(n)
        pendingSkip -= Int64(n)
        return Data(bytes)
    }

    // MARK: Header helpers

    static func cString<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
    }

    /// Octal, or GNU base-256 when the high bit of the first byte is set.
    static func number(_ field: ArraySlice<UInt8>) throws -> Int64 {
        if let first = field.first, first & 0x80 != 0 {
            var v: Int64 = Int64(first & 0x7F)
            for b in field.dropFirst() {
                guard v < Int64.max >> 8 else { throw ArchiveError("Size too large") }
                v = v << 8 | Int64(b)
            }
            return v
        }
        let text = String(decoding: field.prefix { $0 != 0 }, as: UTF8.self).trimmingCharacters(in: .whitespaces)
        if text.isEmpty { return 0 }
        guard let v = Int64(text, radix: 8) else { throw ArchiveError("Bad number in tar header") }
        return v
    }

    static func checksumOK(_ h: [UInt8]) -> Bool {
        guard let stored = try? number(h[148..<156]) else { return false }
        var sum: Int64 = 0
        for (i, b) in h.enumerated() { sum += (148..<156).contains(i) ? 32 : Int64(b) }
        return sum == stored
    }

    /// Pax records are "<len> key=value\n".
    static func paxPath(_ data: [UInt8]) -> String? {
        var i = 0
        while i < data.count {
            guard let space = data[i...].firstIndex(of: 0x20),
                  let len = Int(String(decoding: data[i..<space], as: UTF8.self)), len > 0, i + len <= data.count else { return nil }
            let record = String(decoding: data[(space + 1)..<(i + len - 1)], as: UTF8.self)
            if record.hasPrefix("path=") { return String(record.dropFirst(5)) }
            i += len
        }
        return nil
    }
}
