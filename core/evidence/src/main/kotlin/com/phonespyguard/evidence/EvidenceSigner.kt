package com.phonespyguard.evidence

/**
 * Signs and verifies evidence-entry hashes.
 *
 * On the phone this is backed by a non-exportable, hardware-held key in the
 * Android Keystore (StrongBox where present) — see NFR-SEC-13. The engine side
 * only needs the abstract operations, so the hash-chain and its verification
 * stay pure Kotlin and testable off-device. The signature proves an entry was
 * written by this device's key; combined with the hash chain, any edit,
 * deletion or reorder becomes detectable (FR-EVD-01, FR-EVD-03).
 */
public interface EvidenceSigner {
    /** Identifies the signing key, so an export can name it and a verifier can
     *  select the matching public key. */
    public val keyId: String

    /** Sign the given bytes (an entry hash). */
    public fun sign(data: ByteArray): ByteArray

    /** Verify a signature previously produced by [keyId]'s key. */
    public fun verify(data: ByteArray, signature: ByteArray): Boolean
}
