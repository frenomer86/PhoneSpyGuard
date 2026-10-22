package com.phonespyguard.app.watch

import android.content.Context
import com.phonespyguard.app.security.EncryptedBlobStore
import com.phonespyguard.app.security.KeystoreEvidenceSigner
import com.phonespyguard.evidence.Checkpoint
import com.phonespyguard.evidence.EntryType
import com.phonespyguard.evidence.EvidenceEntry
import com.phonespyguard.evidence.EvidenceExport
import com.phonespyguard.evidence.EvidenceLog
import com.phonespyguard.evidence.EvidenceSigner
import java.io.File

/**
 * Persists the evidence timeline between runs (security review C3), safely
 * (review N3) and in a form a verifier off the phone can check (review H7).
 *
 * The chain logic is the tested core [EvidenceLog]; this class is the encrypted
 * persistence around it. Three safety properties the review asked for:
 *  - a decrypt or parse failure never silently resets the chain — the file is
 *    moved aside and a WATCH_GAP entry records it;
 *  - every append goes through [update], which loads, mutates and saves under a
 *    single process-wide lock, so the scan screen and the background worker
 *    cannot race and lose each other's entries;
 *  - [exportBundleJson] ships the public key and the Keystore attestation chain
 *    alongside the entries, so a bank, lawyer or the `psg-verify` tool can
 *    confirm the record without this phone.
 */
public class EvidenceStore(
    context: Context,
    signer: EvidenceSigner? = null,
) {
    private val chainStore = EncryptedBlobStore(context, CHAIN_FILE)

    // The default on-device signer is the hardware Keystore key, given a durable
    // store for its attestation challenge so an export can carry it (review:
    // real hardware attestation).
    private val signer: EvidenceSigner =
        signer ?: KeystoreEvidenceSigner(challengeStore = BlobChallengeStore(context))

    /** Load the chain, refusing to discard a stored-but-unreadable one. */
    public fun load(): EvidenceLog {
        return when (val r = chainStore.readResult()) {
            is EncryptedBlobStore.ReadResult.Absent -> EvidenceLog(signer = signer)
            is EncryptedBlobStore.ReadResult.Ok -> {
                val parsed = runCatching { EvidenceLog.fromJson(r.text) }.getOrNull()
                if (parsed != null) {
                    EvidenceLog(signer = signer, initial = parsed)
                } else {
                    freshAfterQuarantine("the stored timeline could not be parsed")
                }
            }
            is EncryptedBlobStore.ReadResult.Unreadable ->
                freshAfterQuarantine("the stored timeline could not be decrypted")
        }
    }

    /**
     * Load, mutate and save the chain under one lock so concurrent writers (the
     * scan screen and the watch worker) never clobber each other (review N3).
     */
    public fun update(block: (EvidenceLog) -> Unit) {
        synchronized(WRITE_LOCK) {
            val log = load()
            block(log)
            chainStore.write(log.exportJson())
        }
    }

    public fun entries(): List<EvidenceEntry> = load().all()

    /** A signed checkpoint the owner can send off the device (review H7). */
    public fun checkpoint(): Checkpoint = load().checkpoint()

    /** The whole chain as JSON (entries only) — kept for callers that want it. */
    public fun exportJson(): String = load().exportJson()

    /**
     * A self-verifiable export: entries, a signed checkpoint, the public key and
     * the Keystore attestation chain, so a verifier off the phone can confirm
     * both that the chain is intact and that it was signed by a key that really
     * lives in this phone's hardware (review H7, N6).
     */
    public fun exportBundleJson(): String {
        val log = load()
        val keystore = signer as? KeystoreEvidenceSigner
        return EvidenceExport.build(
            entries = log.all(),
            checkpoint = log.checkpoint(),
            publicKeySpki = keystore?.publicKeyEncoded(),
            attestationChain = keystore?.attestationChain() ?: emptyList(),
            attestationChallenge = keystore?.attestationChallenge(),
            // The Keystore evidence key is EC P-256 signing with ECDSA/SHA-256.
            signatureAlgorithm = "SHA256withECDSA",
            keyAlgorithm = "EC",
        )
    }

    /** Write the verifiable export bundle to [file] for file-based sharing (N6). */
    public fun writeExportFile(file: File) {
        file.writeText(exportBundleJson())
    }

    private fun freshAfterQuarantine(reason: String): EvidenceLog {
        val aside = chainStore.quarantine()
        val log = EvidenceLog(signer = signer)
        log.append(
            type = EntryType.WATCH_GAP,
            summary = "Evidence history could not be read and was set aside",
            details = buildMap {
                put("reason", reason)
                if (aside != null) put("preservedAs", aside)
            },
        )
        chainStore.write(log.exportJson())
        return log
    }

    /**
     * Backs the Keystore signer's attestation challenge with the same encrypted
     * storage the chain uses. The challenge is written once, when the key is
     * first created, and read back for each export.
     */
    private class BlobChallengeStore(context: Context) : KeystoreEvidenceSigner.ChallengeStore {
        private val blob = EncryptedBlobStore(context, CHALLENGE_FILE)
        override fun load(): ByteArray? =
            blob.read()?.let { runCatching { android.util.Base64.decode(it, android.util.Base64.NO_WRAP) }.getOrNull() }
        override fun save(bytes: ByteArray) {
            blob.write(android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP))
        }
    }

    private companion object {
        const val CHAIN_FILE = "evidence-chain.json"
        const val CHALLENGE_FILE = "evidence-attestation-challenge"

        // Process-wide: all EvidenceStore instances serialise writes through this.
        val WRITE_LOCK = Any()
    }
}
