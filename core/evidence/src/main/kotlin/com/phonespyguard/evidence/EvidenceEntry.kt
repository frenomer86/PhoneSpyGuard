package com.phonespyguard.evidence

import kotlinx.serialization.Serializable

/** The kind of thing an evidence entry records (FR-EVD-01, "Life of an alert"). */
public enum class EntryType {
    /** A rule matched or a suspect was scored. */
    FINDING,

    /** The change watcher saw the device differ from its baseline. */
    CHANGE,

    /** The owner answered "I did this" / "I did not". */
    ANSWER,

    /** The owner exported the timeline. */
    EXPORT,

    /** The watch was interrupted and later resumed (FR-WCH-04). */
    WATCH_GAP,

    /** A free-form note. */
    NOTE,
}

/**
 * One append-only entry in the evidence timeline.
 *
 * Each entry is chained to the one before it by [prevHash] and sealed by
 * [entryHash] = SHA-256 of its canonical content; [signature] is that hash
 * signed by the device key. The fields are ordered and serialised
 * deterministically so the same entry always hashes the same way on any device
 * and in any export (FR-EVD-01/02).
 */
@Serializable
public data class EvidenceEntry(
    val seq: Long,
    val timestampMillis: Long,
    val type: EntryType,
    val summary: String,
    val details: Map<String, String>,
    val prevHash: String,
    val entryHash: String,
    val keyId: String,
    /** Base64 (no wrapping) of the signature over the entry-hash bytes. */
    val signature: String,
)
