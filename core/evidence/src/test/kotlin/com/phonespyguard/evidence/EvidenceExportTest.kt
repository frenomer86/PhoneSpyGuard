package com.phonespyguard.evidence

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * Proves the portable export (review H7) can actually be verified off the phone,
 * with only the bundle, by an EC key like the Android Keystore's — and that
 * tampering or truncation is caught. This is the `psg-verify` path, exercised.
 */
class EvidenceExportTest {

    /** An in-process EC P-256 signer, as the Android Keystore key behaves. */
    private class EcSigner(override val keyId: String = "ec-test") : EvidenceSigner {
        val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        override fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private); update(data); sign()
        }
        override fun verify(data: ByteArray, signature: ByteArray): Boolean = runCatching {
            Signature.getInstance("SHA256withECDSA").run { initVerify(keyPair.public); update(data); verify(signature) }
        }.getOrDefault(false)
    }

    private fun buildExport(signer: EcSigner): String {
        val log = EvidenceLog(signer = signer)
        log.append(EntryType.FINDING, "VERY_LIKELY: com.unknownvendor.b", mapOf("signals" to "PSG-BEH-030"))
        log.append(EntryType.CHANGE, "An app gained accessibility access", mapOf("subject" to "com.x"))
        return EvidenceExport.build(
            entries = log.all(),
            checkpoint = log.checkpoint(),
            publicKeySpki = signer.keyPair.public.encoded,
            signatureAlgorithm = "SHA256withECDSA",
            keyAlgorithm = "EC",
        )
    }

    @Test
    fun `a genuine export verifies off-device with only the bundle`() {
        val json = buildExport(EcSigner())
        assertEquals(EvidenceExport.ExportCheck.Ok, EvidenceExport.verify(json))
    }

    @Test
    fun `an edited entry fails verification`() {
        val json = buildExport(EcSigner())
        val tampered = json.replace("An app gained accessibility access", "Nothing happened")
        assertTrue(EvidenceExport.verify(tampered) is EvidenceExport.ExportCheck.Invalid)
    }

    @Test
    fun `a truncated chain fails against its checkpoint`() {
        val signer = EcSigner()
        val log = EvidenceLog(signer = signer)
        log.append(EntryType.FINDING, "one")
        log.append(EntryType.FINDING, "two")
        log.append(EntryType.FINDING, "three")
        val checkpoint = log.checkpoint() // sees 3 entries
        // Export only the first two entries but keep the 3-entry checkpoint.
        val truncated = EvidenceExport.build(
            entries = log.all().take(2),
            checkpoint = checkpoint,
            publicKeySpki = signer.keyPair.public.encoded,
            signatureAlgorithm = "SHA256withECDSA",
            keyAlgorithm = "EC",
        )
        val result = EvidenceExport.verify(truncated)
        assertTrue(result is EvidenceExport.ExportCheck.Invalid, "truncation must be detected")
    }

    @Test
    fun `an export signed by a different key does not verify`() {
        val realJson = buildExport(EcSigner())
        // Swap in a different key's SPKI: the signatures no longer match.
        val otherKey = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val otherSpki = java.util.Base64.getEncoder().encodeToString(otherKey.public.encoded)
        val swapped = realJson.replace(
            Regex("\"publicKeySpki\": \"[^\"]+\""),
            "\"publicKeySpki\": \"$otherSpki\"",
        )
        assertTrue(EvidenceExport.verify(swapped) is EvidenceExport.ExportCheck.Invalid)
    }
}
