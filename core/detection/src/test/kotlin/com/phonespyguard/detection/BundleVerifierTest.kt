package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.time.Instant

class BundleVerifierTest {

    private val payload = """
        {"version":5,"expires":"2099-01-01T00:00:00Z","rules":[
          {"id":"R","severity":"low","contribution":"risk","title":"t","when":{"fact":"a","exists":true}}
        ]}
    """.trimIndent().toByteArray()

    private fun keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun sign(kp: KeyPair, keyId: String, data: ByteArray): BundleSignature {
        val sig = Signature.getInstance("Ed25519").apply {
            initSign(kp.private)
            update(data)
        }
        return BundleSignature(keyId, sig.sign())
    }

    @Test
    fun `accepts a bundle signed by the threshold of trusted keys`() {
        val k1 = keyPair(); val k2 = keyPair(); val k3 = keyPair()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("k1", k1.public.encoded),
                TrustedKey.fromX509("k2", k2.public.encoded),
                TrustedKey.fromX509("k3", k3.public.encoded),
            ),
            threshold = 2,
        )
        val result = verifier.verify(
            payload,
            signatures = listOf(sign(k1, "k1", payload), sign(k2, "k2", payload)),
            installedVersion = 1,
        )
        assertEquals(VerifyResult.Accepted, result)
    }

    @Test
    fun `rejects when below the signature threshold`() {
        val k1 = keyPair(); val k2 = keyPair()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("k1", k1.public.encoded),
                TrustedKey.fromX509("k2", k2.public.encoded),
            ),
            threshold = 2,
        )
        val result = verifier.verify(payload, listOf(sign(k1, "k1", payload)), installedVersion = 1)
        assertInstanceOf(VerifyResult.Rejected::class.java, result)
    }

    @Test
    fun `rejects a signature from an untrusted key`() {
        val trusted = keyPair(); val attacker = keyPair(); val other = keyPair()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("k1", trusted.public.encoded),
                TrustedKey.fromX509("k2", other.public.encoded),
            ),
            threshold = 2,
        )
        // Attacker signs claiming to be k2, but the bytes verify against the real k2 key -> invalid.
        val forged = sign(attacker, "k2", payload)
        val result = verifier.verify(payload, listOf(sign(trusted, "k1", payload), forged), installedVersion = 1)
        assertInstanceOf(VerifyResult.Rejected::class.java, result)
    }

    @Test
    fun `one key under two ids does not satisfy 2-of-3 (L2)`() {
        // A misconfigured trust set lists the same public key twice. Counting
        // distinct public keys, not ids, means its two signatures count once.
        val shared = keyPair(); val other = keyPair()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("id-a", shared.public.encoded),
                TrustedKey.fromX509("id-b", shared.public.encoded),
                TrustedKey.fromX509("id-c", other.public.encoded),
            ),
            threshold = 2,
        )
        val result = verifier.verify(
            payload,
            signatures = listOf(sign(shared, "id-a", payload), sign(shared, "id-b", payload)),
            installedVersion = 1,
        )
        assertInstanceOf(VerifyResult.Rejected::class.java, result)
    }

    @Test
    fun `rejects a tampered payload`() {
        val k1 = keyPair(); val k2 = keyPair()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("k1", k1.public.encoded),
                TrustedKey.fromX509("k2", k2.public.encoded),
            ),
            threshold = 2,
        )
        val sigs = listOf(sign(k1, "k1", payload), sign(k2, "k2", payload))
        val tampered = payload.toString(Charsets.UTF_8).replace("\"risk\"", "\"confirm\"").toByteArray()
        val result = verifier.verify(tampered, sigs, installedVersion = 1)
        assertInstanceOf(VerifyResult.Rejected::class.java, result)
    }

    @Test
    fun `rejects a rollback to an older version`() {
        val k1 = keyPair(); val k2 = keyPair()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("k1", k1.public.encoded),
                TrustedKey.fromX509("k2", k2.public.encoded),
            ),
            threshold = 2,
        )
        val result = verifier.verify(
            payload,
            listOf(sign(k1, "k1", payload), sign(k2, "k2", payload)),
            installedVersion = 99,
        )
        val rejected = assertInstanceOf(VerifyResult.Rejected::class.java, result)
        assertTrue(rejected.reason.contains("older"))
    }

    @Test
    fun `rejects an expired bundle`() {
        val k1 = keyPair(); val k2 = keyPair()
        val expiredPayload = """
            {"version":5,"expires":"2000-01-01T00:00:00Z","rules":[]}
        """.trimIndent().toByteArray()
        val verifier = BundleVerifier(
            trustedKeys = listOf(
                TrustedKey.fromX509("k1", k1.public.encoded),
                TrustedKey.fromX509("k2", k2.public.encoded),
            ),
            threshold = 2,
            clock = { Instant.parse("2026-10-22T00:00:00Z") },
        )
        val result = verifier.verify(
            expiredPayload,
            listOf(sign(k1, "k1", expiredPayload), sign(k2, "k2", expiredPayload)),
            installedVersion = 1,
        )
        val rejected = assertInstanceOf(VerifyResult.Rejected::class.java, result)
        assertTrue(rejected.reason.contains("expired"))
    }
}
