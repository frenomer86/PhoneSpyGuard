package com.phonespyguard.scam

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The scam/SMS launch gate (security review M5/N5, spec section 7), run for real
 * over the labelled dataset. The printed report is what the thesis quotes, with
 * every false alarm and miss listed.
 *
 * Gate: at most 2% of legitimate messages wrongly alarmed (the spec's limit),
 * and the common scam scripts caught.
 */
class ScamEvalTest {

    private fun cases(): List<ScamEval.SmsCase> {
        val text = requireNotNull(javaClass.getResourceAsStream("/scam/sms-eval.json"))
            .readBytes().toString(Charsets.UTF_8)
        return ScamEval.loadCases(text)
    }

    @Test
    fun `scam gate is met and the report is printed`() {
        val report = ScamEval().run(cases())
        println(report.pretty())

        assertTrue(
            report.falseAlarmRate <= 0.02,
            "false-alarm rate ${report.falseAlarmRate} exceeds the 2% gate: ${report.falseAlarms.map { it.text }}",
        )
        assertTrue(
            report.catchRate >= 0.85,
            "scam catch rate ${report.catchRate} too low; missed: ${report.missed.map { it.text }}",
        )
        // The legit OTP deliveries specifically must not be hard-alarmed (N5).
        assertTrue(report.legitTotal >= 30, "evaluation set too small to be meaningful")
    }
}
