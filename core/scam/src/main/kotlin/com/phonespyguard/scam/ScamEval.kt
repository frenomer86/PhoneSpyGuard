package com.phonespyguard.scam

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer

/**
 * Runs the scam checker over a labelled set of real-style SMS and measures its
 * false-alarm and catch rates (security review M5/N5, spec section 7). The
 * dataset is representative — legitimate OTP/bank/mobile-money/personal texts
 * and the common scam scripts, including Ghanaian MoMo — not a leaked corpus;
 * the thesis states that and reports the measured numbers, misses included.
 */
public class ScamEval(private val checker: ScamChecker = ScamChecker()) {

    public enum class Label { LEGIT, SCAM }

    @Serializable
    public data class SmsCase(val text: String, val label: Label, val note: String = "")

    public data class Report(
        val legitTotal: Int,
        val scamTotal: Int,
        /** Legit messages wrongly raised to LIKELY_SCAM / KNOWN_SCAM. */
        val falseAlarms: List<SmsCase>,
        /** Legit messages given a soft CAUTION (not a hard alarm). */
        val legitCautioned: List<SmsCase>,
        /** Scam messages the checker let through as safe / no-link. */
        val missed: List<SmsCase>,
    ) {
        public val falseAlarmRate: Double get() = if (legitTotal == 0) 0.0 else falseAlarms.size.toDouble() / legitTotal
        public val catchRate: Double get() = if (scamTotal == 0) 1.0 else (scamTotal - missed.size).toDouble() / scamTotal

        public fun pretty(): String = buildString {
            appendLine("Phone Spy Guard — scam/SMS evaluation")
            appendLine("-".repeat(52))
            appendLine("Legitimate messages:                 $legitTotal")
            appendLine("  wrongly alarmed (false positives): ${falseAlarms.size} (${pct(falseAlarmRate)})")
            appendLine("  soft caution only:                 ${legitCautioned.size}")
            appendLine("Scam messages:                       $scamTotal")
            appendLine("  caught:                            ${scamTotal - missed.size} (${pct(catchRate)})")
            appendLine("  missed:                            ${missed.size}")
            if (falseAlarms.isNotEmpty()) {
                appendLine("-- false alarms --")
                falseAlarms.forEach { appendLine("  ${it.text}") }
            }
            if (missed.isNotEmpty()) {
                appendLine("-- missed scams --")
                missed.forEach { appendLine("  ${it.text}") }
            }
        }

        private fun pct(v: Double) = "%.1f%%".format(v * 100)
    }

    public fun run(cases: List<SmsCase>): Report {
        val legit = cases.filter { it.label == Label.LEGIT }
        val scam = cases.filter { it.label == Label.SCAM }
        val falseAlarms = mutableListOf<SmsCase>()
        val cautioned = mutableListOf<SmsCase>()
        val missed = mutableListOf<SmsCase>()

        for (c in legit) {
            when (checker.check(c.text).level) {
                ScamLevel.KNOWN_SCAM, ScamLevel.LIKELY_SCAM -> falseAlarms += c
                ScamLevel.CAUTION -> cautioned += c
                else -> Unit
            }
        }
        for (c in scam) {
            val level = checker.check(c.text).level
            if (level == ScamLevel.LIKELY_SAFE || level == ScamLevel.NO_LINK) missed += c
        }
        return Report(legit.size, scam.size, falseAlarms, cautioned, missed)
    }

    public companion object {
        public fun loadCases(json: String): List<SmsCase> =
            Json { ignoreUnknownKeys = true }.decodeFromString(ListSerializer(SmsCase.serializer()), json)
    }
}
