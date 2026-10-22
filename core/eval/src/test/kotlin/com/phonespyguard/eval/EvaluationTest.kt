package com.phonespyguard.eval

import com.phonespyguard.detection.RuleBundle
import com.phonespyguard.detection.RuleBundleParser
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The launch-gate evaluation (security review M6, spec section 7). It runs the
 * real launch rule bundle over the labelled fixtures end-to-end and checks the
 * measured numbers against the spec's own gate. The printed report is what the
 * thesis quotes — it is emitted on every run (showStandardStreams), failures
 * and all.
 *
 * Gate (spec section 7):
 *  - every known stalkerware sample is CONFIRMED (100%);
 *  - at least 80% of behavioural stalkerware is high-risk (>= very likely);
 *  - at most one legitimate/assistive app is high-risk (false alarms);
 *  - no assistive app is ever high-risk.
 */
class EvaluationTest {

    private fun bundle(): RuleBundle {
        val text = requireNotNull(javaClass.getResourceAsStream("/rules/launch-bundle.json"))
            .bufferedReader().readText()
        return RuleBundleParser().parse(text)
    }

    private fun fixtures(): List<EvaluationHarness.Fixture> {
        val text = requireNotNull(javaClass.getResourceAsStream("/eval/eval-fixtures.json"))
            .bufferedReader().readText()
        return EvaluationHarness.loadFixtures(text)
    }

    @Test
    fun `launch gate is met and the report is printed`() {
        val report = EvaluationHarness(bundle()).run(fixtures())

        // The thesis reports these numbers verbatim.
        println(report.pretty())

        assertEquals(
            1.0,
            report.knownDetectionRate,
            "every known stalkerware sample must be CONFIRMED",
        )
        assertTrue(
            report.behaviouralHighRiskRate >= 0.80,
            "behavioural detection ${report.behaviouralHighRiskRate} fell below the 80% gate",
        )
        assertTrue(
            report.falseHighRisk.size <= 1,
            "too many false high-risk alarms: ${report.falseHighRisk.map { it.name }}",
        )
        assertTrue(
            report.assistiveHighRisk.isEmpty(),
            "an assistive app was flagged high-risk: ${report.assistiveHighRisk.map { it.name }}",
        )
    }
}
