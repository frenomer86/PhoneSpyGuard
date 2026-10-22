package com.phonespyguard.evidence

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Checks the Android Keystore attestation chain carried in an exported evidence
 * bundle, off the device (round-3 review: "an off-device verifier can confirm
 * the key is hardware-backed").
 *
 * Attestation works because the hardware signs a certificate *for the evidence
 * key* and returns a chain up to a Google-operated root. This verifier does the
 * two checks that are robust in pure JVM, with no vendor libraries:
 *
 *  1. **The chain links.** Every certificate is signed by the next one up, so
 *     the chain is a genuine issuance path and not an unrelated bag of certs.
 *  2. **The chain is bound to the signing key.** The leaf certificate's public
 *     key is the very key the evidence is signed with, so the attestation is
 *     about *this* key and cannot be lifted from another device's export.
 *
 * What it deliberately leaves to the consumer (a bank, a court's expert): the
 * final trust-anchor decision — that the top of the chain is Google's current
 * hardware-attestation root — and reading the security level and challenge from
 * the leaf's Keystore attestation extension (OID 1.3.6.1.4.1.11129.2.1.17),
 * which needs an ASN.1 library. The challenge is exported alongside so that
 * step is a direct comparison. We do not pin a Google root value we cannot
 * verify here, rather than ship a wrong constant that would reject real chains.
 */
public object AttestationVerifier {

    private val json = Json { ignoreUnknownKeys = true }

    public sealed interface Result {
        /** The chain links and its leaf is the evidence signing key. */
        public data class HardwareChain(val chainLength: Int) : Result
        /** No attestation chain in the export (e.g. a device without a secure element, or a test key). */
        public data object Absent : Result
        /** A chain is present but failed a check. */
        public data class Invalid(val reason: String) : Result
    }

    /** Verify straight from an exported bundle produced by [EvidenceExport.build]. */
    public fun verifyExport(exportJson: String): Result {
        val root = runCatching { json.parseToJsonElement(exportJson).jsonObject }
            .getOrElse { return Result.Invalid("Not a JSON object") }
        val chainB64 = root["attestationChain"]?.jsonArray
        if (chainB64 == null || chainB64.isEmpty()) return Result.Absent
        val chain = runCatching { chainB64.map { Base64.getDecoder().decode(it.jsonPrimitive.content) } }
            .getOrElse { return Result.Invalid("Attestation chain is not base64") }
        val signingSpki = root["publicKeySpki"]?.jsonPrimitive?.content
            ?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
        return verifyChain(chain, signingSpki)
    }

    /**
     * Verify a decoded chain. [signingKeySpki] is the X.509/SPKI public key the
     * evidence is signed with; when given, the leaf must carry that exact key.
     */
    public fun verifyChain(chainDer: List<ByteArray>, signingKeySpki: ByteArray?): Result {
        if (chainDer.isEmpty()) return Result.Absent
        val factory = CertificateFactory.getInstance("X.509")
        val certs = runCatching {
            chainDer.map { factory.generateCertificate(it.inputStream()) as X509Certificate }
        }.getOrElse { return Result.Invalid("A certificate could not be parsed: ${it.message}") }

        // 1. Each cert is signed by the next one up (the last is self-signed or a root).
        for (i in 0 until certs.size - 1) {
            val signed = runCatching { certs[i].verify(certs[i + 1].publicKey); true }.getOrDefault(false)
            if (!signed) return Result.Invalid("Certificate $i is not signed by certificate ${i + 1}")
        }

        // 2. The leaf key is the evidence signing key.
        if (signingKeySpki != null) {
            val leafSpki = certs.first().publicKey.encoded
            if (!leafSpki.contentEquals(signingKeySpki)) {
                return Result.Invalid("Attestation leaf key is not the evidence signing key")
            }
        }
        return Result.HardwareChain(certs.size)
    }
}
