package com.phonespyguard.conformance

import com.phonespyguard.detection.*
import com.phonespyguard.evidence.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class RustConformanceTest {
    private val dir = File(System.getenv("PSG_CONFORMANCE_DIR"))
    private fun read(n: String) = File(dir, n).readText()

    private fun facts(o: JsonObject): Facts {
        val b = Facts.builder()
        for ((k, v) in o) {
            when {
                v is JsonArray -> b.textList(k, v.map { it.jsonPrimitive.content })
                v.jsonPrimitive.isString -> b.text(k, v.jsonPrimitive.content)
                v.jsonPrimitive.booleanOrNull != null -> b.bool(k, v.jsonPrimitive.boolean)
                else -> b.number(k, v.jsonPrimitive.long)
            }
        }
        return b.build()
    }

    @Test fun engineCases() {
        val doc = Json.parseToJsonElement(read("engine-cases.json")).jsonObject
        val engine = DetectionEngine(RuleBundleParser().parse(read(doc["bundle"]!!.jsonPrimitive.content)))
        for (c in doc["cases"]!!.jsonArray.map { it.jsonObject }) {
            val name = c["name"]!!.jsonPrimitive.content
            val ev = engine.evaluate(name, facts(c["facts"]!!.jsonObject))
            assertEquals(c["confidence"]!!.jsonPrimitive.content, ev.verdict.confidence.name, name)
            assertEquals(c["matched"]!!.jsonArray.map { it.jsonPrimitive.content }, ev.verdict.signals.map { it.ruleId }, name)
        }
    }

    @Test fun operatorCases() {
        val doc = Json.parseToJsonElement(read("operator-cases.json")).jsonObject
        doc["cases"]!!.jsonArray.forEachIndexed { i, el ->
            val c = el.jsonObject
            val bundle = """{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[{"id":"R","severity":"low","contribution":"risk","when":${c["when"]}}]}"""
            val ev = DetectionEngine(RuleBundleParser().parse(bundle)).evaluate("s", facts(c["facts"]!!.jsonObject))
            assertEquals(c["matches"]!!.jsonPrimitive.boolean, ev.verdict.signals.isNotEmpty(), "case #$i $c")
        }
    }

    private fun rule(w: String) = """{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[{"id":"R","severity":"low","contribution":"risk","when":$w}]}"""

    @Test fun parseCases() {
        val doc = Json.parseToJsonElement(read("parse-cases.json")).jsonObject
        for (c in doc["cases"]!!.jsonArray.map { it.jsonObject }) {
            val text = when {
                "bundle" in c -> c["bundle"]!!.jsonPrimitive.content
                "nested" in c -> { var w = """{"fact":"a","exists":true}"""; repeat(c["nested"]!!.jsonPrimitive.int) { w = """{"not":$w}""" }; rule(w) }
                else -> rule("""{"all":[${(0 until c["wide"]!!.jsonPrimitive.int).joinToString(",") { """{"fact":"f$it","exists":true}""" }}]}""")
            }
            val ok = runCatching { RuleBundleParser().parse(text) }.isSuccess
            assertEquals(c["accept"]!!.jsonPrimitive.boolean, ok, c["name"]!!.jsonPrimitive.content)
        }
    }

    @Test fun desktopBundleParsesInKotlin() {
        val text = File(dir, "../rules/desktop-bundle.json").takeIf { it.exists() }?.readText() ?: return
        val b = RuleBundleParser().parse(text)
        assertTrue(b.rules.isNotEmpty())
        println("desktop bundle: ${b.rules.size} rules parsed by Kotlin")
    }

    @Test fun evidenceVectors() {
        val companion = EvidenceLog::class.java.declaredClasses.first { it.simpleName == "Companion" }
        val m = companion.declaredMethods.first { it.name.startsWith("canonicalContent") }
        m.isAccessible = true
        val inst = EvidenceLog::class.java.getDeclaredField("Companion").get(null)
        val doc = Json.parseToJsonElement(read("evidence-vectors.json")).jsonObject
        for (v in doc["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val details = v["details"]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }
            val bytes = m.invoke(inst, v["seq"]!!.jsonPrimitive.long, v["timestampMillis"]!!.jsonPrimitive.long,
                EntryType.valueOf(v["type"]!!.jsonPrimitive.content), v["summary"]!!.jsonPrimitive.content,
                details, v["prevHash"]!!.jsonPrimitive.content) as ByteArray
            val hex = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            assertEquals(v["entryHash"]!!.jsonPrimitive.content, hex)
        }
    }

    @Test fun rustWrittenTimelineVerifies() {
        val doc = Json.parseToJsonElement(read("evidence-sample-export.json")).jsonObject
        val pub = KeyFactory.getInstance("Ed25519").generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(doc["publicKeyX509"]!!.jsonPrimitive.content)))
        val verifier = object : EvidenceSigner {
            override val keyId = doc["keyId"]!!.jsonPrimitive.content
            override fun sign(data: ByteArray) = error("verify only")
            override fun verify(data: ByteArray, signature: ByteArray) = Signature.getInstance("Ed25519").run {
                initVerify(pub); update(data); verify(signature) }
        }
        val entries = EvidenceLog.fromJson(doc["entries"].toString())
        assertEquals(ChainCheck.Intact, EvidenceLog.verify(entries, verifier))
        val tampered = entries.toMutableList().also { it[1] = it[1].copy(summary = it[1].summary + "!") }
        assertInstanceOf(ChainCheck.Broken::class.java, EvidenceLog.verify(tampered, verifier))
    }
}
