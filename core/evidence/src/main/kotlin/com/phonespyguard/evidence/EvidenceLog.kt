package com.phonespyguard.evidence

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.util.Base64

/** The genesis "previous hash" for the first entry: 64 hex zeroes. */
private const val GENESIS_HASH: String = "0000000000000000000000000000000000000000000000000000000000000000"

/** The result of checking an exported or in-memory chain (FR-EVD-02/03). */
public sealed interface ChainCheck {
    public data object Intact : ChainCheck

    /** The chain is broken; [atSeq] is the first bad entry and [reason] says how. */
    public data class Broken(val atSeq: Long, val reason: String) : ChainCheck
}

/**
 * An append-only, hash-chained, signed evidence timeline (FR-EVD-01).
 *
 * The log never updates or deletes an entry; it only appends. Because every
 * entry carries the previous entry's hash and is signed, any later edit,
 * deletion or reordering breaks [verify]. The owner can export the whole chain
 * and a verifier — a bank, a lawyer, the app on another device — can confirm it
 * has not been touched (FR-EVD-02).
 *
 * This class holds the chain logic only. Persisting entries to the encrypted
 * database (Room on SQLCipher) is the Android layer's job; it reads and writes
 * these same [EvidenceEntry] records.
 */
public class EvidenceLog(
    private val signer: EvidenceSigner,
    private val clock: () -> Long = System::currentTimeMillis,
    initial: List<EvidenceEntry> = emptyList(),
) {
    private val entries = initial.toMutableList()
    private val json = Json { prettyPrint = false }
    private val base64 = Base64.getEncoder()

    public val size: Int get() = entries.size

    public fun all(): List<EvidenceEntry> = entries.toList()

    /** Append a new entry, chaining and signing it. Returns the stored entry. */
    public fun append(
        type: EntryType,
        summary: String,
        details: Map<String, String> = emptyMap(),
    ): EvidenceEntry {
        val seq = entries.size.toLong()
        val prevHash = entries.lastOrNull()?.entryHash ?: GENESIS_HASH
        val timestamp = clock()

        val entryHashBytes = sha256(
            canonicalContent(seq, timestamp, type, summary, details, prevHash),
        )
        val entryHash = entryHashBytes.toHex()
        val signature = base64.encodeToString(signer.sign(entryHashBytes))

        val entry = EvidenceEntry(
            seq = seq,
            timestampMillis = timestamp,
            type = type,
            summary = summary,
            details = details,
            prevHash = prevHash,
            entryHash = entryHash,
            keyId = signer.keyId,
            signature = signature,
        )
        entries.add(entry)
        return entry
    }

    /**
     * Walk the chain and confirm every link, hash and signature. Returns the
     * first problem found, or [ChainCheck.Intact].
     */
    public fun verify(): ChainCheck = verify(entries, signer)

    /** Export the whole timeline as deterministic JSON (FR-EVD-02). The PDF
     *  rendering is done on-device; both carry the same entries. */
    public fun exportJson(): String = json.encodeToString(entries.toList())

    /**
     * A signed checkpoint of the current head (security review H7). Saving this
     * off the device lets the owner later prove the chain has not been truncated
     * back past this point.
     */
    public fun checkpoint(): Checkpoint {
        val count = entries.size.toLong()
        val lastHash = entries.lastOrNull()?.entryHash ?: GENESIS_HASH
        val timestamp = clock()
        val content = checkpointContent(count, lastHash, timestamp)
        return Checkpoint(
            count = count,
            lastHash = lastHash,
            timestampMillis = timestamp,
            keyId = signer.keyId,
            signature = base64.encodeToString(signer.sign(content)),
        )
    }

    public companion object {
        public fun fromJson(text: String): List<EvidenceEntry> =
            Json.decodeFromString(text)

        /**
         * Confirm a chain still matches a checkpoint saved earlier (security
         * review H7). The chain must verify, end at the checkpoint's last hash,
         * and have at least as many entries — a shorter chain means the newest
         * entries were deleted after the checkpoint was taken.
         */
        public fun verifyAgainstCheckpoint(
            entries: List<EvidenceEntry>,
            signer: EvidenceSigner,
            checkpoint: Checkpoint,
        ): CheckpointCheck {
            val signature = runCatching { Base64.getDecoder().decode(checkpoint.signature) }
                .getOrElse { return CheckpointCheck.Mismatch("Checkpoint signature is not valid base64") }
            val content = checkpointContent(checkpoint.count, checkpoint.lastHash, checkpoint.timestampMillis)
            if (!signer.verify(content, signature)) {
                return CheckpointCheck.Mismatch("Checkpoint signature does not verify")
            }
            if (verify(entries, signer) != ChainCheck.Intact) {
                return CheckpointCheck.Mismatch("Chain does not verify")
            }
            if (entries.size.toLong() < checkpoint.count) {
                return CheckpointCheck.Mismatch(
                    "Chain has ${entries.size} entries, checkpoint saw ${checkpoint.count} — entries were deleted",
                )
            }
            val atCheckpoint = entries.getOrNull((checkpoint.count - 1).toInt())
            if (checkpoint.count > 0 && atCheckpoint?.entryHash != checkpoint.lastHash) {
                return CheckpointCheck.Mismatch("Entry at the checkpoint position does not match its hash")
            }
            return CheckpointCheck.Ok
        }

        private fun checkpointContent(count: Long, lastHash: String, timestampMillis: Long): ByteArray =
            "checkpoint\n$count\n$lastHash\n$timestampMillis".toByteArray(Charsets.UTF_8)

        /**
         * Verify an arbitrary list of entries (e.g. one just imported from an
         * export) against a signer that can check the device key.
         */
        public fun verify(entries: List<EvidenceEntry>, signer: EvidenceSigner): ChainCheck {
            var expectedPrev = GENESIS_HASH
            entries.forEachIndexed { index, entry ->
                if (entry.seq != index.toLong()) {
                    return ChainCheck.Broken(entry.seq, "Sequence number out of order")
                }
                if (entry.prevHash != expectedPrev) {
                    return ChainCheck.Broken(entry.seq, "Previous-hash link does not match")
                }
                val recomputed = sha256(
                    canonicalContent(
                        entry.seq,
                        entry.timestampMillis,
                        entry.type,
                        entry.summary,
                        entry.details,
                        entry.prevHash,
                    ),
                )
                if (recomputed.toHex() != entry.entryHash) {
                    return ChainCheck.Broken(entry.seq, "Entry hash does not match its content")
                }
                val signature = runCatching { Base64.getDecoder().decode(entry.signature) }
                    .getOrElse { return ChainCheck.Broken(entry.seq, "Signature is not valid base64") }
                if (!signer.verify(recomputed, signature)) {
                    return ChainCheck.Broken(entry.seq, "Signature does not verify")
                }
                expectedPrev = entry.entryHash
            }
            return ChainCheck.Intact
        }

        private fun canonicalContent(
            seq: Long,
            timestampMillis: Long,
            type: EntryType,
            summary: String,
            details: Map<String, String>,
            prevHash: String,
        ): ByteArray {
            // Deterministic: fixed field order, details sorted by key, newlines
            // in values escaped so they cannot forge field boundaries.
            val detailBlock = details.toSortedMap().entries.joinToString(";") { (k, v) ->
                "${escape(k)}=${escape(v)}"
            }
            val content = buildString {
                append(seq); append('\n')
                append(timestampMillis); append('\n')
                append(type.name); append('\n')
                append(escape(summary)); append('\n')
                append(detailBlock); append('\n')
                append(prevHash)
            }
            return content.toByteArray(Charsets.UTF_8)
        }

        private fun escape(s: String): String =
            s.replace("\\", "\\\\").replace("\n", "\\n").replace(";", "\\;").replace("=", "\\=")

        private fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)

        private fun ByteArray.toHex(): String =
            joinToString("") { "%02x".format(it) }
    }
}
