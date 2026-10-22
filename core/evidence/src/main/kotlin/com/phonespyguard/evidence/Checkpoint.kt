package com.phonespyguard.evidence

import kotlinx.serialization.Serializable

/**
 * A signed statement of how long the chain was at a moment in time (security
 * review H7): the entry count and the hash of the last entry, signed by the
 * device key.
 *
 * Verifying the chain from the genesis entry proves nobody edited or reordered
 * what remains, but it cannot notice that the newest entries were deleted — a
 * shorter chain still verifies. A checkpoint closes that gap: if the owner sends
 * a checkpoint off the device (an email to themselves, a trusted contact, a
 * timestamping service), anyone can later confirm the chain still has at least
 * [count] entries ending in [lastHash], so truncation back to an earlier point
 * is detectable.
 */
@Serializable
public data class Checkpoint(
    val count: Long,
    val lastHash: String,
    val timestampMillis: Long,
    val keyId: String,
    /** Base64 (no wrapping) of the signature over the checkpoint content bytes. */
    val signature: String,
)

/** The outcome of checking a chain against a previously saved [Checkpoint]. */
public sealed interface CheckpointCheck {
    public data object Ok : CheckpointCheck

    /** The chain no longer matches the checkpoint; [reason] says how. */
    public data class Mismatch(val reason: String) : CheckpointCheck
}
