package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class RuleUpdateFetcherTest {

    private fun keyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private fun sign(kp: KeyPair, data: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").apply { initSign(kp.private); update(data) }.sign()

    private val k1 = keyPair()
    private val k2 = keyPair()
    private val trust = TrustConfig(
        keys = listOf(
            TrustedKey.fromX509("release-1", k1.public.encoded),
            TrustedKey.fromX509("release-2", k2.public.encoded),
        ),
        threshold = 2,
    )

    private fun payload(version: Int): ByteArray =
        """{"version":$version,"expires":"2099-01-01T00:00:00Z","rules":[
             {"id":"R","severity":"low","contribution":"risk","title":"t","when":{"fact":"a","exists":true}}]}"""
            .trimIndent().toByteArray()

    private fun sigFile(payload: ByteArray): ByteArray {
        val b64 = Base64.getEncoder()
        return """{"signatures":[
            {"keyId":"release-1","signature":"${b64.encodeToString(sign(k1, payload))}"},
            {"keyId":"release-2","signature":"${b64.encodeToString(sign(k2, payload))}"}]}"""
            .trimIndent().toByteArray()
    }

    private class MemoryStore : BundleStore {
        var current: StoredUpdate? = null
        override fun read() = current
        override fun write(update: StoredUpdate) { current = update }
        override fun clear() { current = null }
    }

    private class MapTransport(val files: Map<String, ByteArray>) : UpdateTransport {
        override fun get(url: String): ByteArray = files[url] ?: throw java.io.IOException("404 $url")
    }

    private val payloadUrl = "https://example.org/rules/launch-bundle.json"
    private val sigUrl = "https://example.org/rules/launch-bundle.sig.json"

    @Test
    fun `a valid signed update is fetched, verified and installed`() {
        val p = payload(3)
        val store = MemoryStore()
        val service = RuleUpdateService(trust, store)
        val transport = MapTransport(mapOf(payloadUrl to p, sigUrl to sigFile(p)))
        val fetcher = RuleUpdateFetcher(service, transport, payloadUrl, sigUrl)

        val result = fetcher.fetchAndInstall(shippedVersion = 2)
        assertInstanceOf(InstallResult.Installed::class.java, result)
        assertEquals(3, (result as InstallResult.Installed).version)
        assertEquals(3, service.active(RuleBundleParser().parse(payload(2).toString(Charsets.UTF_8)), payload(2)).bundle.version)
    }

    @Test
    fun `a download failure is a refusal, nothing stored`() {
        val store = MemoryStore()
        val fetcher = RuleUpdateFetcher(RuleUpdateService(trust, store), MapTransport(emptyMap()), payloadUrl, sigUrl)
        val result = fetcher.fetchAndInstall(shippedVersion = 2)
        assertInstanceOf(InstallResult.Refused::class.java, result)
        assertNull(store.read())
    }

    @Test
    fun `a bundle whose signatures don't match the payload is refused`() {
        val good = payload(3)
        val tampered = payload(3).toString(Charsets.UTF_8).replace("\"version\":3", "\"version\":4").toByteArray()
        val store = MemoryStore()
        // Serve the tampered payload but signatures over the good one.
        val transport = MapTransport(mapOf(payloadUrl to tampered, sigUrl to sigFile(good)))
        val fetcher = RuleUpdateFetcher(RuleUpdateService(trust, store), transport, payloadUrl, sigUrl)
        assertInstanceOf(InstallResult.Refused::class.java, fetcher.fetchAndInstall(shippedVersion = 2))
        assertNull(store.read())
    }

    @Test
    fun `a malformed signature file is refused`() {
        val p = payload(3)
        val store = MemoryStore()
        val transport = MapTransport(mapOf(payloadUrl to p, sigUrl to "not json".toByteArray()))
        val fetcher = RuleUpdateFetcher(RuleUpdateService(trust, store), transport, payloadUrl, sigUrl)
        assertInstanceOf(InstallResult.Refused::class.java, fetcher.fetchAndInstall(shippedVersion = 2))
        assertNull(store.read())
    }
}
