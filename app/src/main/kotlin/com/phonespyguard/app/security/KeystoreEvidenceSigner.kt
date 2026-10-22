package com.phonespyguard.app.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.phonespyguard.evidence.EvidenceSigner
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature

/**
 * Signs evidence entries with a non-exportable key held in the Android Keystore,
 * in StrongBox where the device has it (NFR-SEC-13). The private key never
 * leaves hardware, so an attacker who copies the database still cannot forge or
 * re-chain entries. The public key is exportable, so an export can be verified
 * off-device.
 */
public class KeystoreEvidenceSigner(
    override val keyId: String = DEFAULT_ALIAS,
    /**
     * Persists the attestation challenge chosen when the key was created, so it
     * can later be written into an export for a verifier to cross-check against
     * the leaf certificate's attestation extension. The app backs this with its
     * encrypted store; null keeps the key fully functional (the challenge is
     * still set on the key, the chain is still real) but the challenge is simply
     * not surfaced for export.
     */
    private val challengeStore: ChallengeStore? = null,
) : EvidenceSigner {

    /** Durable storage for the per-key attestation challenge. */
    public interface ChallengeStore {
        public fun load(): ByteArray?
        public fun save(bytes: ByteArray)
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    init {
        if (!keyStore.containsAlias(keyId)) generateKey()
    }

    override fun sign(data: ByteArray): ByteArray {
        val privateKey = (keyStore.getEntry(keyId, null) as KeyStore.PrivateKeyEntry).privateKey
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(data)
            sign()
        }
    }

    override fun verify(data: ByteArray, signature: ByteArray): Boolean = runCatching {
        val cert = keyStore.getCertificate(keyId) ?: return false
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(cert.publicKey)
            update(data)
            verify(signature)
        }
    }.getOrDefault(false)

    /** The public key, so an exported timeline can be verified on another device. */
    public fun publicKeyEncoded(): ByteArray? =
        keyStore.getCertificate(keyId)?.publicKey?.encoded

    /**
     * The Keystore attestation certificate chain for the signing key (review H7).
     * It lets a verifier off the device confirm the key really lives in this
     * phone's hardware and was not forged, chaining up to Google's attestation
     * root. Empty if the device or key does not support attestation.
     */
    public fun attestationChain(): List<ByteArray> =
        runCatching {
            keyStore.getCertificateChain(keyId)?.map { it.encoded } ?: emptyList()
        }.getOrDefault(emptyList())

    /**
     * The attestation challenge the signing key was generated with (review:
     * real hardware attestation). A verifier confirms the leaf certificate's
     * Keystore attestation extension embeds this exact value, which proves the
     * chain was minted for this key and is not replayed from another device.
     */
    public fun attestationChallenge(): ByteArray? = challengeStore?.load()

    private fun generateKey() {
        // Prefer StrongBox (a dedicated secure element); if the device has none
        // it throws StrongBoxUnavailableException, so fall back to the TEE.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateKey(strongBox = true)
                return
            } catch (_: android.security.keystore.StrongBoxUnavailableException) {
                // fall through to a non-StrongBox key
            }
        }
        generateKey(strongBox = false)
    }

    private fun generateKey(strongBox: Boolean) {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE,
        )
        // A fresh, unpredictable attestation challenge. Without it the hardware
        // returns only a self-signed leaf and attestation is not real; with it,
        // getCertificateChain() returns the full chain up to Google's
        // attestation root whose leaf proves the security level (StrongBox/TEE)
        // and binds this challenge, so an off-device verifier can confirm the
        // key is hardware-backed (round-3 review).
        val challenge = ByteArray(CHALLENGE_BYTES).also { SecureRandom().nextBytes(it) }
        challengeStore?.save(challenge)
        val spec = KeyGenParameterSpec.Builder(keyId, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_ALIAS = "psg_evidence_key"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val CHALLENGE_BYTES = 32
    }
}
