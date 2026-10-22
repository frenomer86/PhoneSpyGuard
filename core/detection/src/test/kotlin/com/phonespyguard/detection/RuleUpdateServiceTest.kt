package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class RuleUpdateServiceTest {

    private fun keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun sign(kp: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").apply { initSign(kp.private); update(data) }.sign()

    private fun bundlePayload(version: Int, expires: String = "2099-01-01T00:00:00Z"): ByteArray =
        """
            {"version":$version,"expires":"$expires","rules":[
              {"id":"R","severity":"low","contribution":"risk","title":"t","when":{"fact":"a","exists":true}}
            ]}
        """.trimIndent().toByteArray()

    private class MemoryStore(var current: StoredUpdate? = null) : BundleStore {
        override fun read(): StoredUpdate? = current
        override fun write(update: StoredUpdate) { current = update }
        override fun clear() { current = null }
    }

    private val k1 = keyPair()
    private val k2 = keyPair()
    private val k3 = keyPair()
    private val trust = TrustConfig(
        keys = listOf(
            TrustedKey.fromX509("release-1", k1.public.encoded),
            TrustedKey.fromX509("release-2", k2.public.encoded),
            TrustedKey.fromX509("release-3", k3.public.encoded),
        ),
        threshold = 2,
    )

    private val parser = RuleBundleParser()
    private val shippedPayload = bundlePayload(2)
    private val shipped = parser.parse(shippedPayload.toString(Charsets.UTF_8))

    private fun sigs(payload: ByteArray, vararg kps: Pair<String, KeyPair>): List<BundleSignature> =
        kps.map { (id, kp) -> BundleSignature(id, sign(kp, payload)) }

    @Test
    fun `a 2-of-3 signed newer update is installed and becomes active`() {
        val store = MemoryStore()
        val service = RuleUpdateService(trust, store)
        val update = bundlePayload(3)
        val result = service.tryInstall(update, sigs(update, "release-1" to k1, "release-2" to k2), shippedVersion = 2)
        assertInstanceOf(InstallResult.Installed::class.java, result)
        assertEquals(3, (result as InstallResult.Installed).version)

        val active = service.active(shipped, shippedPayload)
        assertEquals("update", active.source)
        assertEquals(3, active.bundle.version)
        assertNull(active.warning)
    }

    @Test
    fun `a single signature is refused and nothing is stored`() {
        val store = MemoryStore()
        val service = RuleUpdateService(trust, store)
        val update = bundlePayload(3)
        val result = service.tryInstall(update, sigs(update, "release-1" to k1), shippedVersion = 2)
        assertInstanceOf(InstallResult.Refused::class.java, result)
        assertNull(store.read())
        assertEquals("shipped", service.active(shipped, shippedPayload).source)
    }

    @Test
    fun `a tampered payload is refused — signatures no longer match`() {
        val store = MemoryStore()
        val service = RuleUpdateService(trust, store)
        val update = bundlePayload(3)
        val goodSigs = sigs(update, "release-1" to k1, "release-2" to k2)
        val tampered = update.toString(Charsets.UTF_8).replace("\"version\":3", "\"version\":9").toByteArray()
        val result = service.tryInstall(tampered, goodSigs, shippedVersion = 2)
        assertInstanceOf(InstallResult.Refused::class.java, result)
        assertNull(store.read())
    }

    @Test
    fun `a rollback below the shipped version is refused`() {
        val store = MemoryStore()
        val service = RuleUpdateService(trust, store)
        val update = bundlePayload(1) // older than shipped 2
        val result = service.tryInstall(update, sigs(update, "release-1" to k1, "release-2" to k2), shippedVersion = 2)
        assertInstanceOf(InstallResult.Refused::class.java, result)
        assertTrue((result as InstallResult.Refused).reason.contains("older"))
    }

    @Test
    fun `a stored update older than a bumped shipped bundle is dropped with a warning`() {
        // Device installed a v3 update, then an app update bumped the shipped bundle to v4.
        val update = bundlePayload(3)
        val store = MemoryStore(StoredUpdate(update, sigs(update, "release-1" to k1, "release-2" to k2)))
        val service = RuleUpdateService(trust, store)
        val shippedV4Payload = bundlePayload(4)
        val shippedV4 = parser.parse(shippedV4Payload.toString(Charsets.UTF_8))
        val active = service.active(shippedV4, shippedV4Payload)
        assertEquals("shipped", active.source)
        assertEquals(4, active.bundle.version)
        assertTrue(active.warning!!.contains("no longer valid"))
    }

    @Test
    fun `an untrusted key cannot help reach the threshold`() {
        val store = MemoryStore()
        val service = RuleUpdateService(trust, store)
        val attacker = keyPair()
        val update = bundlePayload(3)
        val result = service.tryInstall(
            update,
            listOf(BundleSignature("release-1", sign(k1, update)), BundleSignature("release-9", sign(attacker, update))),
            shippedVersion = 2,
        )
        assertInstanceOf(InstallResult.Refused::class.java, result)
    }

    @Test
    fun `the shipped trust set parses and is 2-of-3`() {
        // The real trusted-keys.json we ship (same as the desktop/iPhone apps).
        val text = readResource("/rules/trusted-keys.json")
        val config = TrustConfig.parse(text)
        assertEquals(2, config.threshold)
        assertEquals(3, config.keys.size)
    }

    @Test
    fun `a trust file listing a revoked development key is refused (H6)`() {
        // The three H6 dev keys whose private halves leaked. Even a well-formed
        // 2-of-3 trust file is refused if it lists one, so a fetched update signed
        // with a leaked key can never be trusted.
        val revoked = """
            {"threshold":2,"keys":[
              {"keyId":"release-1","publicKey":"MCowBQYDK2VwAyEAPLV2Dk5hwc2ugW7RzGg3G5aMZKdcOVKCtMqZdHzcmXE="},
              {"keyId":"release-2","publicKey":"MCowBQYDK2VwAyEAX0dJ10X/B16/Y31cicRNqzhZkt6Yl8E26g/YFHDgiYc="},
              {"keyId":"release-3","publicKey":"MCowBQYDK2VwAyEAcJvqgASL7C/W7RQdqK+bdcLzgZy44g3pPytVr5umJi0="}
            ]}
        """.trimIndent()
        val ex = assertThrows(BundleRejected::class.java) { TrustConfig.parse(revoked) }
        assertTrue(ex.message!!.contains("revoked"), ex.message)
    }

    @Test
    fun `a trust file below a 2-of-3 threshold is refused`() {
        val text = readResource("/rules/trusted-keys.json").replace("\"threshold\": 2", "\"threshold\": 1")
        assertThrows(BundleRejected::class.java) { TrustConfig.parse(text) }
    }

    @Test
    fun `the signature file format parses`() {
        val update = bundlePayload(3)
        val s1 = Base64.getEncoder().encodeToString(sign(k1, update))
        val json = """{"signatures":[{"keyId":"release-1","signature":"$s1"}]}"""
        val parsed = SignatureFile.parse(json)
        assertEquals(1, parsed.size)
        assertEquals("release-1", parsed.first().keyId)
    }

    private fun readResource(path: String): String =
        requireNotNull(javaClass.getResourceAsStream(path)) { "missing $path" }
            .readBytes().toString(Charsets.UTF_8)
}
