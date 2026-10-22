package com.phonespyguard.eval

import com.phonespyguard.detection.Confidence
import com.phonespyguard.detection.DetectionEngine
import com.phonespyguard.detection.FactKeys
import com.phonespyguard.detection.Facts
import com.phonespyguard.detection.RuleBundle
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Runs the detection engine over a labelled set of app profiles and measures how
 * it does against the spec's launch gate (security review M6). It is the
 * methodology the thesis reports: real stalkerware samples, the Play top-500 and
 * assistive apps slot into the same fixture format and the same metrics.
 *
 * The harness mirrors the Android collector's derivation so a fixture only needs
 * the raw device facts: it applies the bundle's signed indicator set to the
 * package/cert, and computes the surveillance-power count, exactly as the app
 * does. That makes the measurement end-to-end, not a test of hand-set facts.
 */
public class EvaluationHarness(private val bundle: RuleBundle) {

    private val engine = DetectionEngine(bundle)

    /** What a fixture is really (its ground truth). */
    public enum class Label {
        /** A known stalkerware product (matched by package/cert). Must be CONFIRMED. */
        KNOWN_STALKERWARE,

        /** Stalkerware caught by behaviour, not a name. Must be at least VERY_LIKELY. */
        BEHAVIOURAL_STALKERWARE,

        /** An ordinary legitimate app. Must not be high-risk. */
        LEGITIMATE,

        /** An assistive tool (e.g. screen reader). Must never be high-risk. */
        ASSISTIVE,
    }

    public data class Case(val name: String, val label: Label, val confidence: Confidence)

    public data class Report(
        val cases: List<Case>,
        val knownDetectionRate: Double,
        val behaviouralHighRiskRate: Double,
        val falseHighRisk: List<Case>,
        val assistiveHighRisk: List<Case>,
    ) {
        public val knownTotal: Int get() = cases.count { it.label == Label.KNOWN_STALKERWARE }
        public val behaviouralTotal: Int get() = cases.count { it.label == Label.BEHAVIOURAL_STALKERWARE }
        public val legitTotal: Int get() = cases.count { it.label == Label.LEGITIMATE || it.label == Label.ASSISTIVE }

        public fun pretty(): String = buildString {
            appendLine("Phone Spy Guard — detection evaluation (fixtures)")
            appendLine("-".repeat(52))
            appendLine("Known stalkerware named (CONFIRMED):   ${pct(knownDetectionRate)} of $knownTotal")
            appendLine("Behavioural caught (>= very likely):   ${pct(behaviouralHighRiskRate)} of $behaviouralTotal")
            appendLine("False high-risk on $legitTotal legit/assistive apps: ${falseHighRisk.size}")
            appendLine("Assistive apps wrongly high-risk:      ${assistiveHighRisk.size}")
            appendLine("-".repeat(52))
            cases.forEach { appendLine("  ${it.label.name.padEnd(24)} ${it.confidence.name.padEnd(12)} ${it.name}") }
        }

        private fun pct(v: Double) = "%.0f%%".format(v * 100)
    }

    public fun run(fixtures: List<Fixture>): Report {
        val cases = fixtures.map { fx ->
            val facts = deriveFacts(fx)
            Case(fx.name, fx.label, engine.evaluate(fx.name, facts).verdict.confidence)
        }
        val known = cases.filter { it.label == Label.KNOWN_STALKERWARE }
        val behavioural = cases.filter { it.label == Label.BEHAVIOURAL_STALKERWARE }
        val legitAndAssistive = cases.filter { it.label == Label.LEGITIMATE || it.label == Label.ASSISTIVE }

        return Report(
            cases = cases,
            knownDetectionRate = rate(known) { it.confidence == Confidence.CONFIRMED },
            behaviouralHighRiskRate = rate(behavioural) { it.confidence.isHighRisk() },
            falseHighRisk = legitAndAssistive.filter { it.confidence.isHighRisk() },
            assistiveHighRisk = cases.filter { it.label == Label.ASSISTIVE && it.confidence.isHighRisk() },
        )
    }

    /** Mirror the collector: apply the signed indicators and compute the power count. */
    private fun deriveFacts(fx: Fixture): Facts {
        val b = Facts.builder()
        // Raw facts from the fixture.
        for ((k, v) in fx.facts) {
            when (v) {
                is JsonPrimitive -> when {
                    v.booleanOrNull != null -> b.bool(k, v.boolean())
                    v.longOrNull != null -> b.number(k, v.longOrNull!!)
                    else -> b.text(k, v.content)
                }
                else -> b.text(k, v.toString())
            }
        }
        // Indicator-derived identity facts (as AppFactsCollector does). An
        // unpinned allow-list match is honoured only for a genuine system app,
        // never on a claimed install source, exactly as the on-device collector
        // computes it (review N2 / round-3 spoofed-source finding).
        val isSystem = flag(fx, FactKeys.IS_SYSTEM_APP)
        val cls = bundle.indicators.classify(fx.pkg, fx.cert, isSystemApp = isSystem)
        b.bool(FactKeys.KNOWN_STALKERWARE_MATCH, cls.knownStalkerware)
        b.bool(FactKeys.MERCENARY_INDICATOR_MATCH, cls.mercenaryMatch)
        b.bool(FactKeys.IS_SCREEN_READER, cls.isScreenReader)
        b.bool(FactKeys.IS_PARENTAL_CONTROL, cls.isParentalControl)
        b.bool(FactKeys.IS_KNOWN_GOOD_KEYBOARD, cls.isKnownGoodKeyboard)
        b.text(FactKeys.PACKAGE, fx.pkg)
        // Derived surveillance-power count.
        val powerCount = listOf(
            flag(fx, FactKeys.ACCESSIBILITY_ENABLED),
            flag(fx, FactKeys.DEVICE_ADMIN),
            flag(fx, FactKeys.NOTIFICATION_ACCESS),
            flag(fx, FactKeys.DEFAULT_SMS),
        ).count { it }
        b.number(FactKeys.SURVEILLANCE_POWER_COUNT, powerCount.toLong())
        return b.build()
    }

    private fun flag(fx: Fixture, key: String): Boolean =
        (fx.facts[key] as? JsonPrimitive)?.booleanOrNull == true

    private fun rate(cases: List<Case>, predicate: (Case) -> Boolean): Double =
        if (cases.isEmpty()) 1.0 else cases.count(predicate).toDouble() / cases.size

    private fun Confidence.isHighRisk() = this == Confidence.CONFIRMED || this == Confidence.VERY_LIKELY

    private fun JsonPrimitive.boolean() = booleanOrNull ?: content.toBoolean()

    @Serializable
    public data class Fixture(
        val name: String,
        val label: Label,
        val pkg: String = "com.example",
        val cert: String? = null,
        val facts: Map<String, JsonElement> = emptyMap(),
    )

    public companion object {
        private val json = Json { ignoreUnknownKeys = true }

        public fun loadFixtures(text: String): List<Fixture> {
            val root = json.parseToJsonElement(text) as JsonObject
            val arr = root["fixtures"]!!
            return json.decodeFromJsonElement(
                kotlinx.serialization.builtins.ListSerializer(Fixture.serializer()),
                arr,
            )
        }
    }
}
