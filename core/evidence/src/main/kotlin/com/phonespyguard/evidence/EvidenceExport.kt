package com.phonespyguard.evidence

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * The portable, self-verifiable evidence export (security review H7).
 *
 * The bundle carries the entries, a signed checkpoint, the signing key's public
 * key and — on a phone — its Keystore attestation chain. That is everything a
 * verifier off the device needs: [verify] reconstructs the public key from the
 * bundle and confirms the hash chain and the checkpoint without the phone, the
 * app, or any trust in the sender. This is the logic the `psg-verify` tool and a
 * bank or lawyer's checker run; keeping it here, in pure Kotlin, means it is
 * exercised by the same tests as the chain itself rather than only living in
 * untested Android code.
 */
public object EvidenceExport {

    public const val FORMAT: String = "phone-spy-guard.evidence.v1"

    private val pretty = Json { prettyPrint = true }
    private val compact = Json { prettyPrint = false }

    /** The outcome of verifying an export. */
    public sealed interface ExportCheck {
        public data object Ok : ExportCheck
        public data class Invalid(val reason: String) : ExportCheck
    }

    /**
     * Build the export JSON. [publicKeySpki] is the X.509/SPKI-encoded public
     * key; [signatureAlgorithm] and [keyAlgorithm] name how it signs (e.g.
     * "SHA256withECDSA"/"EC" on Android, "Ed25519"/"Ed25519" in tests) so a
     * verifier can reconstruct and use it.
     */
    public fun build(
        entries: List<EvidenceEntry>,
        checkpoint: Checkpoint,
        publicKeySpki: ByteArray?,
        attestationChain: List<ByteArray> = emptyList(),
        signatureAlgorithm: String,
        keyAlgorithm: String,
        /**
         * The attestation challenge the signing key was generated with. A
         * verifier that parses the leaf certificate's Keystore attestation
         * extension can confirm it embeds this exact value, which proves the
         * chain was issued for this key and is not replayed (review: real
         * hardware attestation). Null on platforms/keys without attestation.
         */
        attestationChallenge: ByteArray? = null,
    ): String {
        val b64 = Base64.getEncoder()
        val entryArray = compact.encodeToJsonElement(
            kotlinx.serialization.builtins.ListSerializer(EvidenceEntry.serializer()),
            entries,
        ) as JsonArray
        val bundle = buildJsonObject {
            put("format", FORMAT)
            put("keyId", checkpoint.keyId)
            put("signatureAlgorithm", signatureAlgorithm)
            put("keyAlgorithm", keyAlgorithm)
            publicKeySpki?.let { put("publicKeySpki", b64.encodeToString(it)) }
            if (attestationChain.isNotEmpty()) {
                put("attestationChain", buildJsonArray { attestationChain.forEach { add(b64.encodeToString(it)) } })
            }
            attestationChallenge?.let { put("attestationChallenge", b64.encodeToString(it)) }
            put(
                "checkpoint",
                buildJsonObject {
                    put("count", checkpoint.count)
                    put("lastHash", checkpoint.lastHash)
                    put("timestampMillis", checkpoint.timestampMillis)
                    put("keyId", checkpoint.keyId)
                    put("signature", checkpoint.signature)
                },
            )
            put("entries", entryArray)
        }
        return pretty.encodeToString(JsonObject.serializer(), bundle)
    }

    /**
     * Verify an export off-device: reconstruct the public key from the bundle,
     * confirm the chain links/hashes/signatures, and confirm the signed
     * checkpoint matches (so truncation is caught).
     */
    public fun verify(json: String): ExportCheck {
        val root = runCatching { compact.parseToJsonElement(json).jsonObject }
            .getOrElse { return ExportCheck.Invalid("Not a JSON object") }
        if (root["format"]?.jsonPrimitive?.content != FORMAT) {
            return ExportCheck.Invalid("Unknown export format")
        }
        val spkiB64 = root["publicKeySpki"]?.jsonPrimitive?.content
            ?: return ExportCheck.Invalid("Export has no public key to verify against")
        val sigAlg = root["signatureAlgorithm"]?.jsonPrimitive?.content
            ?: return ExportCheck.Invalid("Export does not name its signature algorithm")
        val keyAlg = root["keyAlgorithm"]?.jsonPrimitive?.content
            ?: return ExportCheck.Invalid("Export does not name its key algorithm")
        val keyId = root["keyId"]?.jsonPrimitive?.content ?: ""

        val verifier = runCatching {
            val spki = Base64.getDecoder().decode(spkiB64)
            val publicKey = KeyFactory.getInstance(keyAlg).generatePublic(X509EncodedKeySpec(spki))
            PublicKeyVerifier(keyId, publicKey, sigAlg)
        }.getOrElse { return ExportCheck.Invalid("Public key could not be read: ${it.message}") }

        val entries = runCatching {
            EvidenceLog.fromJson((root["entries"] as JsonArray).toString())
        }.getOrElse { return ExportCheck.Invalid("Entries could not be read: ${it.message}") }

        when (val chain = EvidenceLog.verify(entries, verifier)) {
            is ChainCheck.Broken -> return ExportCheck.Invalid("Chain broken at ${chain.atSeq}: ${chain.reason}")
            ChainCheck.Intact -> Unit
        }

        val cpObj = root["checkpoint"]?.jsonObject ?: return ExportCheck.Invalid("Export has no checkpoint")
        val checkpoint = Checkpoint(
            count = cpObj["count"]!!.jsonPrimitive.content.toLong(),
            lastHash = cpObj["lastHash"]!!.jsonPrimitive.content,
            timestampMillis = cpObj["timestampMillis"]!!.jsonPrimitive.content.toLong(),
            keyId = cpObj["keyId"]!!.jsonPrimitive.content,
            signature = cpObj["signature"]!!.jsonPrimitive.content,
        )
        return when (val cp = EvidenceLog.verifyAgainstCheckpoint(entries, verifier, checkpoint)) {
            CheckpointCheck.Ok -> ExportCheck.Ok
            is CheckpointCheck.Mismatch -> ExportCheck.Invalid(cp.reason)
        }
    }

    /** An [EvidenceSigner] that can only verify, from a bundled public key. */
    private class PublicKeyVerifier(
        override val keyId: String,
        private val publicKey: java.security.PublicKey,
        private val signatureAlgorithm: String,
    ) : EvidenceSigner {
        override fun sign(data: ByteArray): ByteArray =
            throw UnsupportedOperationException("A verifier cannot sign")

        override fun verify(data: ByteArray, signature: ByteArray): Boolean = runCatching {
            Signature.getInstance(signatureAlgorithm).run {
                initVerify(publicKey)
                update(data)
                verify(signature)
            }
        }.getOrDefault(false)
    }
}
