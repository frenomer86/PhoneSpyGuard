package com.phonespyguard.detection

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant

/** One Ed25519 signature over the exact bundle payload bytes. */
public data class BundleSignature(
    /** Identifies which release key signed, for key rotation. */
    val keyId: String,
    val signature: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is BundleSignature && keyId == other.keyId && signature.contentEquals(other.signature))

    override fun hashCode(): Int = 31 * keyId.hashCode() + signature.contentHashCode()
}

/** A trusted release key: an Ed25519 public key with its id. */
public data class TrustedKey(val keyId: String, val publicKey: PublicKey) {
    public companion object {
        /** Build from a raw X.509-encoded Ed25519 public key (SubjectPublicKeyInfo). */
        public fun fromX509(keyId: String, x509: ByteArray): TrustedKey {
            val key = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(x509))
            return TrustedKey(keyId, key)
        }
    }
}

/** The outcome of verifying a candidate bundle before it is applied. */
public sealed interface VerifyResult {
    public data object Accepted : VerifyResult
    public data class Rejected(val reason: String) : VerifyResult
}

/**
 * Decides whether a signed bundle may be applied (FR-RUL-01, NFR-SEC-15).
 *
 * A bundle is accepted only when:
 *  - at least [threshold] distinct trusted keys have each signed the exact
 *    payload bytes (default 2-of-3) — counted by distinct *public key*, not by
 *    key id, so a trust set that lists one key under two ids cannot satisfy the
 *    threshold on its own (security review L2),
 *  - the parsed bundle has not expired, and
 *  - its version is not older than the version already installed (no rollback).
 *
 * The detection engine itself has no network access; this gate is the only way
 * rules change, so a compromised rule server still cannot push anything the
 * release keys did not sign.
 */
public class BundleVerifier(
    private val trustedKeys: List<TrustedKey>,
    private val threshold: Int = 2,
    private val clock: () -> Instant = Instant::now,
) {
    private val parser = RuleBundleParser()

    public fun verify(
        payload: ByteArray,
        signatures: List<BundleSignature>,
        installedVersion: Int,
    ): VerifyResult {
        // Count distinct public keys that signed, not distinct key ids: two ids
        // sharing one key still count once, so 2-of-3 means two separate keys.
        val validPublicKeys = mutableSetOf<String>()
        for (sig in signatures) {
            val key = trustedKeys.firstOrNull { it.keyId == sig.keyId } ?: continue
            if (ed25519Verifies(key.publicKey, payload, sig.signature)) {
                validPublicKeys.add(key.publicKey.encoded.toHex())
            }
        }
        if (validPublicKeys.size < threshold) {
            return VerifyResult.Rejected(
                "Needs $threshold valid signatures from distinct keys, found ${validPublicKeys.size}",
            )
        }

        val bundle = try {
            parser.parse(payload.toString(Charsets.UTF_8))
        } catch (e: BundleRejected) {
            return VerifyResult.Rejected(e.message ?: "Malformed bundle")
        }

        if (bundle.version < installedVersion) {
            return VerifyResult.Rejected(
                "Bundle version ${bundle.version} is older than installed $installedVersion",
            )
        }
        if (!bundle.expiresAt.isAfter(clock())) {
            return VerifyResult.Rejected("Bundle expired at ${bundle.expiresAt}")
        }
        return VerifyResult.Accepted
    }

    private fun ed25519Verifies(key: PublicKey, payload: ByteArray, signature: ByteArray): Boolean =
        runCatching {
            Signature.getInstance("Ed25519").run {
                initVerify(key)
                update(payload)
                verify(signature)
            }
        }.getOrDefault(false)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
