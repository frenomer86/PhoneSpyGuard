package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RuleBundleParserTest {

    private val parser = RuleBundleParser()

    @Test
    fun `parses the shipped launch bundle`() {
        val text = readResource("/rules/launch-bundle.json")
        val bundle = parser.parse(text)
        assertEquals(2, bundle.version)
        assertTrue(bundle.rules.size >= 7)
        val hidden = bundle.rules.first { it.id == "PSG-BEH-014" }
        assertEquals(Severity.HIGH, hidden.severity)
        assertEquals(Contribution.STRONG, hidden.contribution)
        assertTrue(hidden.condition is Condition.All)
        // The signed indicator set is parsed alongside the rules (C1).
        assertTrue(bundle.indicators.stalkerware.isNotEmpty())
        assertTrue(bundle.indicators.screenReaders.isNotEmpty())
        // An innocent rule carries the ids it explains (H5).
        val innocent = bundle.rules.first { it.id == "PSG-INNOCENT-001" }
        assertTrue(innocent.explains.contains("PSG-RISK-040"))
    }

    @Test
    fun `explains is empty when absent or null`() {
        val json = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"A","severity":"low","contribution":"risk","when":{"fact":"a","exists":true}},
              {"id":"B","severity":"low","contribution":"innocent","explains":null,"when":{"fact":"b","exists":true}}
            ]}
        """.trimIndent()
        val bundle = parser.parse(json)
        assertTrue(bundle.rules.all { it.explains.isEmpty() })
    }

    @Test
    fun `explains must be an array of strings`() {
        val notArray = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"B","severity":"low","contribution":"innocent","explains":"X","when":{"fact":"b","exists":true}}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { parser.parse(notArray) }

        val notStrings = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"B","severity":"low","contribution":"innocent","explains":[5],"when":{"fact":"b","exists":true}}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { parser.parse(notStrings) }
    }

    @Test
    fun `explains over the limit is rejected`() {
        val ids = (1..65).joinToString(",") { "\"R$it\"" }
        val json = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"B","severity":"low","contribution":"innocent","explains":[$ids],"when":{"fact":"b","exists":true}}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { parser.parse(json) }
    }

    @Test
    fun `explains on a non-innocent rule is rejected`() {
        val json = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"B","severity":"high","contribution":"strong","explains":["X"],"when":{"fact":"b","exists":true}}
            ]}
        """.trimIndent()
        val ex = assertThrows(BundleRejected::class.java) { parser.parse(json) }
        assertTrue(ex.message!!.contains("innocent"))
    }

    @Test
    fun `a non-object rule entry is rejected, not crashed`() {
        val json = """{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[42]}"""
        assertThrows(BundleRejected::class.java) { parser.parse(json) }
    }

    @Test
    fun `a non-object when is rejected, not crashed (L1)`() {
        val json = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"R","severity":"low","contribution":"risk","when":"always"}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { parser.parse(json) }
    }

    @Test
    fun `contains with a non-string value is rejected, not crashed`() {
        val json = """
            {"version":1,"expires":"2099-01-01T00:00:00Z","rules":[
              {"id":"R","severity":"low","contribution":"risk","when":{"fact":"a","contains":5}}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { parser.parse(json) }
    }

    @Test
    fun `rejects a bundle with no version`() {
        val ex = assertThrows(BundleRejected::class.java) {
            parser.parse("""{"expires":"2027-01-01T00:00:00Z","rules":[]}""")
        }
        assertTrue(ex.message!!.contains("version"))
    }

    @Test
    fun `rejects a bad expiry`() {
        assertThrows(BundleRejected::class.java) {
            parser.parse("""{"version":1,"expires":"not-a-date","rules":[]}""")
        }
    }

    @Test
    fun `rejects an unknown operator`() {
        val json = """
            {"version":1,"expires":"2027-01-01T00:00:00Z","rules":[
              {"id":"R","severity":"low","contribution":"risk","when":{"fact":"a","wat":1}}
            ]}
        """.trimIndent()
        val ex = assertThrows(BundleRejected::class.java) { parser.parse(json) }
        assertTrue(ex.message!!.contains("operator"))
    }

    @Test
    fun `rejects an unknown contribution`() {
        val json = """
            {"version":1,"expires":"2027-01-01T00:00:00Z","rules":[
              {"id":"R","severity":"low","contribution":"spy","when":{"fact":"a","exists":true}}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { parser.parse(json) }
    }

    @Test
    fun `rejects a bundle that is too big`() {
        val tiny = RuleBundleParser(BundleLimits(maxBytes = 10))
        assertThrows(BundleRejected::class.java) {
            tiny.parse("""{"version":1,"expires":"2027-01-01T00:00:00Z","rules":[]}""")
        }
    }

    @Test
    fun `rejects a rule nested past the depth limit`() {
        val shallow = RuleBundleParser(BundleLimits(maxDepth = 2))
        val json = """
            {"version":1,"expires":"2027-01-01T00:00:00Z","rules":[
              {"id":"R","severity":"low","contribution":"risk","when":
                {"all":[{"all":[{"all":[{"fact":"a","exists":true}]}]}]}}
            ]}
        """.trimIndent()
        val ex = assertThrows(BundleRejected::class.java) { shallow.parse(json) }
        assertTrue(ex.message!!.contains("deep"))
    }

    @Test
    fun `rejects too many condition nodes`() {
        val fewNodes = RuleBundleParser(BundleLimits(maxConditionNodes = 2))
        val json = """
            {"version":1,"expires":"2027-01-01T00:00:00Z","rules":[
              {"id":"R","severity":"low","contribution":"risk","when":
                {"all":[{"fact":"a","exists":true},{"fact":"b","exists":true},{"fact":"c","exists":true}]}}
            ]}
        """.trimIndent()
        assertThrows(BundleRejected::class.java) { fewNodes.parse(json) }
    }

    private fun readResource(path: String): String =
        requireNotNull(javaClass.getResourceAsStream(path)) { "missing $path" }
            .readBytes().toString(Charsets.UTF_8)
}
