import Foundation

/// Something that hands out raw bytes in chunks: a file being read from disk,
/// or bytes already in memory. `nil` means end of input.
public protocol ByteSource: AnyObject {
    func nextChunk() throws -> [UInt8]?
}

/// Reads a file in 1 MiB chunks, so a multi-hundred-megabyte sysdiagnose
/// archive never has to fit in the phone's memory.
public final class FileByteSource: ByteSource {
    private let handle: FileHandle
    private let chunkSize: Int

    public init(url: URL, chunkSize: Int = 1 << 20) throws {
        handle = try FileHandle(forReadingFrom: url)
        self.chunkSize = chunkSize
    }

    deinit { try? handle.close() }

    public func nextChunk() throws -> [UInt8]? {
        let data = handle.readData(ofLength: chunkSize)
        return data.isEmpty ? nil : [UInt8](data)
    }
}

public final class DataByteSource: ByteSource {
    private var data: [UInt8]?
    private let chunkSize: Int
    private var offset = 0

    public init(_ data: Data, chunkSize: Int = 1 << 16) {
        self.data = [UInt8](data)
        self.chunkSize = chunkSize
    }

    public func nextChunk() throws -> [UInt8]? {
        guard let d = data, offset < d.count else { return nil }
        let end = min(offset + chunkSize, d.count)
        defer { offset = end }
        return Array(d[offset..<end])
    }
}

public struct ArchiveError: Error, CustomStringConvertible, Equatable {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// A stream of decompressed (or plain) bytes.
public protocol ByteStream: AnyObject {
    /// Read up to `max` bytes; an empty result means end of stream.
    func read(max: Int) throws -> [UInt8]
}

/// Passes the source through unchanged (an uncompressed .tar).
public final class PlainStream: ByteStream {
    private let source: ByteSource
    private var buffer: [UInt8] = []
    private var pos = 0
    private var prefix: [UInt8]

    init(source: ByteSource, prefix: [UInt8] = []) {
        self.source = source
        self.prefix = prefix
    }

    public func read(max: Int) throws -> [UInt8] {
        if !prefix.isEmpty {
            let n = min(max, prefix.count)
            defer { prefix.removeFirst(n) }
            return Array(prefix[0..<n])
        }
        if pos >= buffer.count {
            guard let next = try source.nextChunk() else { return [] }
            buffer = next
            pos = 0
        }
        let n = min(max, buffer.count - pos)
        defer { pos += n }
        return Array(buffer[pos..<pos + n])
    }
}

// MARK: - Bit reader

final class BitReader {
    private let source: ByteSource
    private var chunk: [UInt8] = []
    private var pos = 0
    private(set) var bitBuf: UInt64 = 0
    private(set) var bitCount = 0
    private var eof = false

    init(source: ByteSource, prefix: [UInt8] = []) {
        self.source = source
        self.chunk = prefix
    }

    @inline(__always)
    private func nextByte() throws -> UInt8? {
        if pos >= chunk.count {
            if eof { return nil }
            guard let c = try source.nextChunk() else { eof = true; return nil }
            chunk = c
            pos = 0
            if chunk.isEmpty { return try nextByte() }
        }
        let b = chunk[pos]
        pos += 1
        return b
    }

    /// Fill the bit buffer to at least `n` bits if input allows; never throws
    /// at end of input (the caller decides whether a short read is an error).
    @inline(__always)
    func fill(_ n: Int) throws {
        while bitCount < n, bitCount <= 56 {
            guard let b = try nextByte() else { return }
            bitBuf |= UInt64(b) << UInt64(bitCount)
            bitCount += 8
        }
    }

    @inline(__always)
    func bits(_ n: Int) throws -> Int {
        if n == 0 { return 0 }
        try fill(n)
        guard bitCount >= n else { throw ArchiveError("Compressed data ends early") }
        let v = Int(bitBuf & ((1 << UInt64(n)) - 1))
        bitBuf >>= UInt64(n)
        bitCount -= n
        return v
    }

    @inline(__always)
    func drop(_ n: Int) {
        bitBuf >>= UInt64(n)
        bitCount -= n
    }

    func alignToByte() {
        drop(bitCount % 8)
    }

    /// One whole byte after `alignToByte()`, or nil at clean end of input.
    func byteAligned() throws -> UInt8? {
        if bitCount >= 8 { return UInt8(try bits(8)) }
        precondition(bitCount == 0)
        return try nextByte()
    }

    func requireByte() throws -> UInt8 {
        guard let b = try byteAligned() else { throw ArchiveError("Archive ends early") }
        return b
    }
}

// MARK: - Huffman tables

struct Huffman {
    static let fastBits = 9
    /// symbol << 4 | length for codes up to `fastBits` long; 0 = slow path.
    var fast: [UInt16]
    var counts: [Int]   // codes per length, index 0...15
    var symbols: [Int]  // symbols ordered by code

    init(lengths: [Int]) throws {
        counts = [Int](repeating: 0, count: 16)
        for l in lengths { counts[l] += 1 }
        counts[0] = 0
        var left = 1
        for len in 1...15 {
            left <<= 1
            left -= counts[len]
            if left < 0 { throw ArchiveError("Over-subscribed Huffman code") }
        }
        var offs = [Int](repeating: 0, count: 16)
        for len in 1..<15 { offs[len + 1] = offs[len] + counts[len] }
        symbols = [Int](repeating: 0, count: lengths.count)
        for (sym, l) in lengths.enumerated() where l != 0 {
            symbols[offs[l]] = sym
            offs[l] += 1
        }
        // Fast table over bit-reversed canonical codes.
        fast = [UInt16](repeating: 0, count: 1 << Self.fastBits)
        var code = 0
        var nextCode = [Int](repeating: 0, count: 16)
        for len in 1...15 {
            code = (code + counts[len - 1]) << 1
            nextCode[len] = code
        }
        for (sym, l) in lengths.enumerated() where l != 0 && l <= Self.fastBits {
            let c = nextCode[l]
            nextCode[l] += 1
            var r = 0
            for i in 0..<l where c & (1 << i) != 0 { r |= 1 << (l - 1 - i) }
            var k = r
            while k < (1 << Self.fastBits) {
                fast[k] = UInt16(sym << 4 | l)
                k += 1 << l
            }
        }
    }

    @inline(__always)
    func decode(_ br: BitReader) throws -> Int {
        try br.fill(15)
        let entry = Int(fast[Int(br.bitBuf & UInt64((1 << Self.fastBits) - 1))])
        let len = entry & 15
        if len != 0, len <= br.bitCount {
            br.drop(len)
            return entry >> 4
        }
        // Slow path (codes longer than fastBits): canonical decode bit by bit.
        var code = 0, first = 0, index = 0
        var buf = br.bitBuf
        for l in 1...15 {
            guard l <= br.bitCount else { break }
            code |= Int(buf & 1)
            buf >>= 1
            let count = counts[l]
            if code - first < count {
                br.drop(l)
                return symbols[index + code - first]
            }
            index += count
            first += count
            first <<= 1
            code <<= 1
        }
        throw ArchiveError("Invalid Huffman code")
    }
}

// MARK: - Inflate (RFC 1951)

/// A streaming DEFLATE decoder in plain Swift, so the same code runs on the
/// phone and in the Linux test suite. It decodes on demand: `read(max:)` only
/// inflates as much as it needs, and keeps a 32 KiB window, never the whole
/// output.
final class Inflater {
    private let br: BitReader
    private var window = [UInt8](repeating: 0, count: 1 << 15)
    private var wpos = 0
    private var out: [UInt8] = []
    private var outPos = 0
    private var lastBlock = false
    private enum State { case header, stored(Int), huffman(Huffman, Huffman), done }
    private var state = State.header
    /// Running CRC-32 of the output, checked against the gzip trailer.
    private(set) var crc = CRC32()
    private(set) var produced: UInt64 = 0

    static let lengthBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
    static let lengthExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
    static let distBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
    static let distExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
    static let fixedLit: Huffman = {
        var l = [Int](repeating: 8, count: 288)
        for i in 144..<256 { l[i] = 9 }
        for i in 256..<280 { l[i] = 7 }
        return try! Huffman(lengths: l)
    }()
    static let fixedDist = try! Huffman(lengths: [Int](repeating: 5, count: 30))

    init(reader: BitReader) {
        br = reader
    }

    var finished: Bool {
        if case .done = state { return outPos >= out.count }
        return false
    }

    func read(max: Int) throws -> [UInt8] {
        while out.count - outPos < max {
            if case .done = state { break }
            try step(target: max)
        }
        let n = min(max, out.count - outPos)
        let result = Array(out[outPos..<outPos + n])
        outPos += n
        if outPos > (1 << 16) {
            out.removeFirst(outPos)
            outPos = 0
        }
        return result
    }

    @inline(__always)
    private func emit(_ b: UInt8) {
        window[wpos & 0x7FFF] = b
        wpos &+= 1
        out.append(b)
    }

    private func step(target: Int) throws {
        let start = out.count
        switch state {
        case .done:
            return
        case .header:
            if lastBlock {
                state = .done
                return
            }
            lastBlock = try br.bits(1) == 1
            switch try br.bits(2) {
            case 0:
                br.alignToByte()
                let len = try br.bits(16)
                let nlen = try br.bits(16)
                guard len == (~nlen & 0xFFFF) else { throw ArchiveError("Stored block length check failed") }
                state = .stored(len)
            case 1:
                state = .huffman(Self.fixedLit, Self.fixedDist)
            case 2:
                state = try dynamicTables()
            default:
                throw ArchiveError("Invalid deflate block type")
            }
        case .stored(var remaining):
            while remaining > 0, out.count - outPos < target {
                emit(UInt8(try br.bits(8)))
                remaining -= 1
            }
            state = remaining == 0 ? .header : .stored(remaining)
        case .huffman(let lit, let dist):
            while out.count - outPos < target {
                let sym = try lit.decode(br)
                if sym < 256 {
                    emit(UInt8(sym))
                } else if sym == 256 {
                    state = .header
                    break
                } else {
                    let li = sym - 257
                    guard li < 29 else { throw ArchiveError("Invalid length code") }
                    let length = Self.lengthBase[li] + (try br.bits(Self.lengthExtra[li]))
                    let ds = try dist.decode(br)
                    guard ds < 30 else { throw ArchiveError("Invalid distance code") }
                    let distance = Self.distBase[ds] + (try br.bits(Self.distExtra[ds]))
                    guard distance <= wpos, distance <= 32768 else { throw ArchiveError("Distance too far back") }
                    for _ in 0..<length { emit(window[(wpos &- distance) & 0x7FFF]) }
                }
            }
        }
        if out.count > start {
            crc.update(out[start..<out.count])
            produced += UInt64(out.count - start)
        }
    }

    private func dynamicTables() throws -> State {
        let hlit = try br.bits(5) + 257
        let hdist = try br.bits(5) + 1
        let hclen = try br.bits(4) + 4
        guard hlit <= 286, hdist <= 30 else { throw ArchiveError("Bad dynamic block counts") }
        let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
        var clens = [Int](repeating: 0, count: 19)
        for i in 0..<hclen { clens[order[i]] = try br.bits(3) }
        let clh = try Huffman(lengths: clens)
        var lengths = [Int]()
        lengths.reserveCapacity(hlit + hdist)
        while lengths.count < hlit + hdist {
            let sym = try clh.decode(br)
            switch sym {
            case 0...15:
                lengths.append(sym)
            case 16:
                guard let prev = lengths.last else { throw ArchiveError("Repeat with no previous length") }
                lengths.append(contentsOf: repeatElement(prev, count: 3 + (try br.bits(2))))
            case 17:
                lengths.append(contentsOf: repeatElement(0, count: 3 + (try br.bits(3))))
            default:
                lengths.append(contentsOf: repeatElement(0, count: 11 + (try br.bits(7))))
            }
        }
        guard lengths.count == hlit + hdist else { throw ArchiveError("Code lengths overrun") }
        guard lengths[256] != 0 else { throw ArchiveError("No end-of-block code") }
        return .huffman(try Huffman(lengths: Array(lengths[0..<hlit])), try Huffman(lengths: Array(lengths[hlit...])))
    }
}

// MARK: - gzip (RFC 1952)

/// Decompresses a .gz stream (including multi-member files), checking every
/// member's CRC-32 and length.
public final class GzipStream: ByteStream {
    private let br: BitReader
    private var inflater: Inflater?
    private var ended = false
    private var members = 0

    init(reader: BitReader) {
        br = reader
    }

    public func read(max: Int) throws -> [UInt8] {
        while !ended {
            if inflater == nil {
                guard try readHeader() else { ended = true; break }
                members += 1
                inflater = Inflater(reader: br)
            }
            let chunk = try inflater!.read(max: max)
            if !chunk.isEmpty { return chunk }
            try readTrailer()
            inflater = nil
        }
        return []
    }

    /// Returns false at a clean end of input (no further member).
    private func readHeader() throws -> Bool {
        br.alignToByte()
        guard let id1 = try br.byteAligned() else { return false }
        let id2 = try br.requireByte()
        guard id1 == 0x1F, id2 == 0x8B else {
            if members > 0 && id1 == 0 { return false } // zero padding after the last member
            throw ArchiveError("Not a gzip file")
        }
        guard try br.requireByte() == 8 else { throw ArchiveError("Unknown gzip compression method") }
        let flags = try br.requireByte()
        for _ in 0..<6 { _ = try br.requireByte() } // mtime, xfl, os
        if flags & 0x04 != 0 {
            let xlen = Int(try br.requireByte()) | Int(try br.requireByte()) << 8
            for _ in 0..<xlen { _ = try br.requireByte() }
        }
        if flags & 0x08 != 0 { while try br.requireByte() != 0 {} }
        if flags & 0x10 != 0 { while try br.requireByte() != 0 {} }
        if flags & 0x02 != 0 { _ = try br.requireByte(); _ = try br.requireByte() }
        return true
    }

    private func readTrailer() throws {
        br.alignToByte()
        var v = [UInt32]()
        for _ in 0..<2 {
            var x: UInt32 = 0
            for i in 0..<4 { x |= UInt32(try br.requireByte()) << UInt32(8 * i) }
            v.append(x)
        }
        guard let inf = inflater else { return }
        guard v[0] == inf.crc.value else { throw ArchiveError("gzip CRC check failed: the archive is damaged") }
        guard v[1] == UInt32(truncatingIfNeeded: inf.produced) else { throw ArchiveError("gzip length check failed") }
    }
}

/// Opens a byte source as plain or gzip-compressed bytes, by its magic number.
public enum ArchiveStreams {
    public static func open(_ source: ByteSource) throws -> ByteStream {
        var head = [UInt8]()
        while head.count < 2, let c = try source.nextChunk() { head.append(contentsOf: c) }
        if head.count >= 2, head[0] == 0x1F, head[1] == 0x8B {
            return GzipStream(reader: BitReader(source: source, prefix: head))
        }
        return PlainStream(source: source, prefix: head)
    }
}

// MARK: - CRC-32

struct CRC32 {
    private static let table: [UInt32] = (0..<256).map { n -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    private var state: UInt32 = 0xFFFF_FFFF

    var value: UInt32 { state ^ 0xFFFF_FFFF }

    mutating func update<S: Sequence>(_ bytes: S) where S.Element == UInt8 {
        var c = state
        Self.table.withUnsafeBufferPointer { t in
            for b in bytes { c = t[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
        }
        state = c
    }
}
