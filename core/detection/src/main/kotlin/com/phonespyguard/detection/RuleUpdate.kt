package com.phonespyguard.detection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.Instant
import java.util.Base64

/**
 * The release trust set an install ships with: the Ed25519 public keys that may
 * sign a rule update, and how many distinct keys must sign (FR-RUL-01,
 * NFR-SEC-15). This is the *same* `trusted-keys.json` the desktop and iPhone
 * apps ship, so one signed update verifies identically on every platform.
 *
 * Format (matches the desktop `TrustFile`):
 * ```json
 * { "threshold": 2, "keys": [ { "keyId": "release-1", "publicKey": "<base64 X.509 SPKI>" } ] }
 * ```
 */
public data class TrustConfig(
    val keys: List<TrustedKey>,
    val threshold: Int,
) {
    public companion object {
        private val json = Json { ignoreUnknownKeys = true }

        /** Parse a `trusted-keys.json`. Throws [BundleRejected] on any malformed field. */
        public fun parse(text: String): TrustConfig {
            val root = runCatching { json.parseToJsonElement(text).jsonObject }
                .getOrElse { throw BundleRejected("trusted-keys is not a JSON object") }
            val threshold = root["threshold"]?.jsonPrimitive?.longOrNull?.toInt()
                ?: throw BundleRejected("trusted-keys has no integer 'threshold'")
            if (threshold < 1) throw BundleRejected("trusted-keys threshold must be at least 1")
            val keyArray = root["keys"]?.jsonArray
                ?: throw BundleRejected("trusted-keys has no 'keys' array")
            val keys = keyArray.map { el ->
                val obj = el.jsonObject
                val keyId = obj["keyId"]?.jsonPrimitive?.content
                    ?: throw BundleRejected("a trusted key has no 'keyId'")
                val b64 = obj["publicKey"]?.jsonPrimitive?.content
                    ?: throw BundleRejected("trusted key $keyId has no 'publicKey'")
                val der = runCatching { Base64.getDecoder().decode(b64) }
                    .getOrElse { throw BundleRejected("trusted key $keyId publicKey is not base64") }
                runCatching { TrustedKey.fromX509(keyId, der) }
                    .getOrElse { throw BundleRejected("trusted key $keyId is not an Ed25519 public key") }
            }
            if (keys.size < threshold) {
                throw BundleRejected("trusted-keys lists ${keys.size} keys but needs a threshold of $threshold")
            }
            return TrustConfig(keys, threshold)
        }
    }
}

/**
 * The detached signatures that accompany a bundle payload. Format (matches the
 * desktop `SignatureFile`):
 * ```json
 * { "signatures": [ { "keyId": "release-1", "signature": "<base64>" } ] }
 * ```
 */
public object SignatureFile {
    private val json = Json { ignoreUnknownKeys = true }

    public fun parse(text: String): List<BundleSignature> {
        val root = runCatching { json.parseToJsonElement(text).jsonObject }
            .getOrElse { throw BundleRejected("signatures is not a JSON object") }
        val arr = root["signatures"]?.jsonArray
            ?: throw BundleRejected("signatures has no 'signatures' array")
        return arr.map { el ->
            val obj = el.jsonObject
            val keyId = obj["keyId"]?.jsonPrimitive?.content
                ?: throw BundleRejected("a signature has no 'keyId'")
            val b64 = obj["signature"]?.jsonPrimitive?.content
                ?: throw BundleRejected("signature from $keyId has no 'signature'")
            val bytes = runCatching { Base64.getDecoder().decode(b64) }
                .getOrElse { throw BundleRejected("signature from $keyId is not base64") }
            BundleSignature(keyId, bytes)
        }
    }
}

/** A downloaded update held on disk: the exact payload bytes and its signatures. */
public data class StoredUpdate(
    val payload: ByteArray,
    val signatures: List<BundleSignature>,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (other is StoredUpdate && payload.contentEquals(other.payload) && signatures == other.signatures)

    override fun hashCode(): Int = 31 * payload.contentHashCode() + signatures.hashCode()
}

/** Where a verified update is persisted. The app backs this with encrypted storage. */
public interface BundleStore {
    public fun read(): StoredUpdate?
    public fun write(update: StoredUpdate)
    public fun clear()
}

/** The result of offering an update to [RuleUpdateService.tryInstall]. */
public sealed interface InstallResult {
    /** Accepted, verified and persisted. The new rules take effect on the next load. */
    public data class Installed(val version: Int) : InstallResult
    /** Rejected; nothing was stored. The app keeps running on the bundle it had. */
    public data class Refused(val reason: String) : InstallResult
}

/** Which bundle is in force, and why. */
public data class ActiveBundle(
    val bundle: RuleBundle,
    /** "update" when a verified downloaded bundle is in force, else "shipped". */
    val source: String,
    /** A stored update that no longer verifies, surfaced so the app can warn. */
    val warning: String? = null,
)

/**
 * Applies signed rule updates on Android, the same way the desktop does
 * (`rules.rs::load`): a downloaded bundle is used only after
 * [BundleVerifier] confirms the 2-of-3 signatures, a version no older than the
 * one in force, and a non-expired payload. The shipped bundle (trusted via the
 * APK signature) is always the floor, so a verified update can only move the
 * rules *forward*, never roll them back, and a tampered or stale update is
 * refused while the shipped rules keep working.
 *
 * All of this is pure JVM so it is unit-tested off-device; the app supplies only
 * the [BundleStore] (encrypted file) and the bytes it downloaded.
 */
public class RuleUpdateService(
    private val trust: TrustConfig,
    private val store: BundleStore,
    private val clock: () -> Instant = Instant::now,
) {
    private val parser = RuleBundleParser()
    private val verifier = BundleVerifier(trust.keys, trust.threshold, clock)

    /**
     * Offer a freshly downloaded update. [shippedVersion] is the version of the
     * bundle baked into the app. The candidate must verify and be no older than
     * whichever is newer of the shipped bundle and any update already stored.
     */
    public fun tryInstall(
        payload: ByteArray,
        signatures: List<BundleSignature>,
        shippedVersion: Int,
    ): InstallResult {
        val floor = maxOf(shippedVersion, storedVersionOrNull() ?: Int.MIN_VALUE)
        return when (val r = verifier.verify(payload, signatures, installedVersion = floor)) {
            is VerifyResult.Accepted -> {
                val version = parser.parse(payload.toString(Charsets.UTF_8)).version
                store.write(StoredUpdate(payload, signatures))
                InstallResult.Installed(version)
            }
            is VerifyResult.Rejected -> InstallResult.Refused(r.reason)
        }
    }

    /**
     * The best bundle that verifies: a stored update if it still passes against
     * the shipped version, otherwise the shipped bundle. A stored update that no
     * longer verifies (expired, or now older than a shipped bump) is reported as
     * a [ActiveBundle.warning] and the shipped bundle is used.
     */
    public fun active(shipped: RuleBundle, shippedPayload: ByteArray): ActiveBundle {
        val stored = store.read() ?: return ActiveBundle(shipped, "shipped")
        return when (val r = verifier.verify(stored.payload, stored.signatures, installedVersion = shipped.version)) {
            is VerifyResult.Accepted ->
                ActiveBundle(parser.parse(stored.payload.toString(Charsets.UTF_8)), "update")
            is VerifyResult.Rejected ->
                ActiveBundle(shipped, "shipped", warning = "Stored rule update no longer valid: ${r.reason}")
        }
    }

    private fun storedVersionOrNull(): Int? = runCatching {
        val s = store.read() ?: return null
        parser.parse(s.payload.toString(Charsets.UTF_8)).version
    }.getOrNull()
}
