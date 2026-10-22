package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScoringTest {

    private val scoring = Scoring()

    private fun signal(
        id: String,
        c: Contribution,
        sev: Severity = Severity.HIGH,
        explains: List<String> = emptyList(),
    ) = MatchedSignal(id, id, sev, c, explains)

    @Test
    fun `a confirm signal is always confirmed`() {
        val v = scoring.classify("com.x", listOf(signal("known", Contribution.CONFIRM)))
        assertEquals(Confidence.CONFIRMED, v.confidence)
    }

    @Test
    fun `confirm beats an innocent explanation`() {
        val v = scoring.classify(
            "com.x",
            listOf(signal("known", Contribution.CONFIRM), signal("inn", Contribution.INNOCENT)),
        )
        assertEquals(Confidence.CONFIRMED, v.confidence)
    }

    @Test
    fun `a strong signal with no innocent explanation is very likely`() {
        val v = scoring.classify("com.x", listOf(signal("beh", Contribution.STRONG)))
        assertEquals(Confidence.VERY_LIKELY, v.confidence)
    }

    @Test
    fun `a strong signal explained away by name is unlikely`() {
        val v = scoring.classify(
            "com.x",
            listOf(
                signal("beh", Contribution.STRONG),
                signal("inn", Contribution.INNOCENT, explains = listOf("beh")),
            ),
        )
        assertEquals(Confidence.UNLIKELY, v.confidence)
        assertTrue(v.innocentExplanations.isNotEmpty())
    }

    @Test
    fun `an innocent that does not name the strong signal does not excuse it`() {
        // Screen-reader innocent explains the accessibility power, not an
        // unrelated "uploads while screen off" strong signal (security review H5).
        val v = scoring.classify(
            "com.x",
            listOf(
                signal("uploads", Contribution.STRONG),
                signal("screenreader", Contribution.INNOCENT, explains = listOf("accessibility")),
            ),
        )
        assertEquals(Confidence.VERY_LIKELY, v.confidence)
    }

    @Test
    fun `partial explanation leaves the unexplained strong signal`() {
        val v = scoring.classify(
            "com.x",
            listOf(
                signal("accessibility", Contribution.RISK, Severity.MEDIUM),
                signal("uploads", Contribution.STRONG),
                signal("inn", Contribution.INNOCENT, explains = listOf("accessibility")),
            ),
        )
        // The RISK is explained, the STRONG is not -> very likely.
        assertEquals(Confidence.VERY_LIKELY, v.confidence)
    }

    @Test
    fun `an innocent naming a confirm rule does not downgrade it`() {
        val v = scoring.classify(
            "com.x",
            listOf(
                signal("known", Contribution.CONFIRM),
                signal("inn", Contribution.INNOCENT, explains = listOf("known")),
            ),
        )
        assertEquals(Confidence.CONFIRMED, v.confidence)
    }

    @Test
    fun `a risk explained by name is unlikely`() {
        val v = scoring.classify(
            "com.x",
            listOf(
                signal("accessibility", Contribution.RISK, Severity.MEDIUM),
                signal("inn", Contribution.INNOCENT, explains = listOf("accessibility")),
            ),
        )
        assertEquals(Confidence.UNLIKELY, v.confidence)
    }

    @Test
    fun `a risky power with no activity is possible`() {
        val v = scoring.classify("com.x", listOf(signal("kbd", Contribution.RISK, Severity.MEDIUM)))
        assertEquals(Confidence.POSSIBLE, v.confidence)
    }

    @Test
    fun `no signals is unlikely`() {
        val v = scoring.classify("com.x", emptyList())
        assertEquals(Confidence.UNLIKELY, v.confidence)
        assertTrue(v.concerning.isEmpty())
    }

    @Test
    fun `concerning excludes innocent signals`() {
        val v = scoring.classify(
            "com.x",
            listOf(signal("beh", Contribution.STRONG), signal("inn", Contribution.INNOCENT)),
        )
        assertEquals(1, v.concerning.size)
        assertEquals("beh", v.concerning.single().ruleId)
    }
}
