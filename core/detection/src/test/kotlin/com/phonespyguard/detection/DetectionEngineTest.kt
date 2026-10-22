package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * End-to-end checks: load the shipped launch bundle and confirm each kind of
 * subject lands in the right confidence level, matching the worked examples in
 * the spec (pages 11-12).
 */
class DetectionEngineTest {

    private lateinit var engine: DetectionEngine

    @BeforeEach
    fun setUp() {
        val text = requireNotNull(javaClass.getResourceAsStream("/rules/launch-bundle.json"))
            .readBytes().toString(Charsets.UTF_8)
        val bundle = RuleBundleParser().parse(text)
        engine = DetectionEngine(bundle)
    }

    @Test
    fun `known stalkerware is confirmed`() {
        val facts = Facts.builder()
            .text("app.package", "com.evil.track")
            .bool("app.known_stalkerware_match", true)
            .build()
        val eval = engine.evaluate("com.evil.track", facts)
        assertEquals(Confidence.CONFIRMED, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-KNOWN-001" })
    }

    @Test
    fun `hidden sideloaded screen-reader uploading is very likely`() {
        val facts = Facts.builder()
            .text("app.package", "com.sys.update.helper")
            .bool("app.accessibility_enabled", true)
            .bool("app.has_launcher_icon", false)
            .text("app.install_source", "sideload")
            .bool("app.uploads_screen_off", true)
            .build()
        val eval = engine.evaluate("com.sys.update.helper", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        // Both the hidden-screen-reader rule and the uploads rule should fire.
        val ids = eval.verdict.signals.map { it.ruleId }
        assertTrue(ids.containsAll(listOf("PSG-BEH-014", "PSG-BEH-021")))
    }

    @Test
    fun `a lone unrecognised keyboard is possible`() {
        val facts = Facts.builder()
            .text("app.package", "com.keys.board")
            .bool("app.is_keyboard", true)
            .bool("app.is_known_good_keyboard", false)
            .build()
        val eval = engine.evaluate("com.keys.board", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
    }

    @Test
    fun `a recognised mainstream keyboard is not flagged`() {
        val facts = Facts.builder()
            .text("app.package", "com.google.android.inputmethod.latin")
            .bool("app.is_keyboard", true)
            .bool("app.is_known_good_keyboard", true)
            .build()
        val eval = engine.evaluate("com.google.android.inputmethod.latin", facts)
        assertEquals(Confidence.UNLIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.concerning.isEmpty())
    }

    @Test
    fun `a known screen reader with only accessibility is unlikely`() {
        val facts = Facts.builder()
            .text("app.package", "com.google.android.marvin.talkback")
            .bool("app.accessibility_enabled", true)
            .bool("app.has_launcher_icon", false)
            .bool("app.is_screen_reader", true)
            .number("app.surveillance_power_count", 1)
            .build()
        val eval = engine.evaluate("com.google.android.marvin.talkback", facts)
        assertEquals(Confidence.UNLIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.innocentExplanations.any { it.ruleId == "PSG-INNOCENT-001" })
    }

    @Test
    fun `a screen reader that uploads while screen off is not excused (H5)`() {
        // Being an allow-listed screen reader explains accessibility, not
        // exfiltration while the screen is off — that strong signal stands.
        val facts = Facts.builder()
            .text("app.package", "com.google.android.marvin.talkback")
            .bool("app.accessibility_enabled", true)
            .bool("app.uploads_screen_off", true)
            .bool("app.is_screen_reader", true)
            .build()
        val eval = engine.evaluate("com.google.android.marvin.talkback", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
    }

    @Test
    fun `sideloaded app with two surveillance powers is very likely (C2)`() {
        // The most common stalkerware setup: sideloaded, keeps an icon renamed to
        // look like a system app, relies on notification access + device admin.
        val facts = Facts.builder()
            .text("app.package", "com.android.systemservice2")
            .text("app.install_source", "sideload")
            .bool("app.has_launcher_icon", true)
            .number("app.surveillance_power_count", 2)
            .build()
        val eval = engine.evaluate("com.android.systemservice2", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-BEH-030" })
    }

    @Test
    fun `sideloaded app with one surveillance power is possible (C2)`() {
        val facts = Facts.builder()
            .text("app.install_source", "sideload")
            .number("app.surveillance_power_count", 1)
            .bool("app.has_launcher_icon", true)
            .build()
        val eval = engine.evaluate("com.x", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-010" })
    }

    @Test
    fun `a hidden sideloaded app holding a power is very likely (C2)`() {
        val facts = Facts.builder()
            .text("app.install_source", "sideload")
            .bool("app.has_launcher_icon", false)
            .number("app.surveillance_power_count", 1)
            .build()
        val eval = engine.evaluate("com.x", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-BEH-031" })
    }

    @Test
    fun `a hidden store or system app holding a power is only possible, not very likely (N1)`() {
        // A watch companion plugin or a system helper: no icon, holds notification
        // access, but came from the store. It must not be called "Very likely spying".
        val facts = Facts.builder()
            .text("app.install_source", "play")
            .bool("app.has_launcher_icon", false)
            .number("app.surveillance_power_count", 1)
            .build()
        val eval = engine.evaluate("com.watch.plugin", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-031" })
        assertTrue(eval.verdict.signals.none { it.ruleId == "PSG-BEH-031" })
    }

    @Test
    fun `mercenary indicator match is confirmed (FR-DEV-08)`() {
        val facts = Facts.builder()
            .bool("app.mercenary_indicator_match", true)
            .build()
        val eval = engine.evaluate("com.x", facts)
        assertEquals(Confidence.CONFIRMED, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-KNOWN-002" })
    }

    @Test
    fun `parental control on the owner phone is possible with an explanation (H5)`() {
        val facts = Facts.builder()
            .text("app.package", "com.qustodio.qustodioapp")
            .bool("app.accessibility_enabled", true)
            .bool("app.is_parental_control", true)
            .build()
        val eval = engine.evaluate("com.qustodio.qustodioapp", facts)
        // The accessibility RISK is explained, but parental-control-on-own-phone
        // is itself a RISK that is not explained away.
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-030" })
        assertTrue(eval.verdict.innocentExplanations.any { it.ruleId == "PSG-INNOCENT-002" })
    }

    @Test
    fun `a faked install source is possible (H4)`() {
        val facts = Facts.builder()
            .text("app.install_source", "play")
            .bool("app.install_source_mismatch", true)
            .build()
        val eval = engine.evaluate("com.x", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-003" })
    }

    @Test
    fun `a certificate change on update is very likely (M2)`() {
        val facts = Facts.builder()
            .bool("app.cert_changed_on_update", true)
            .build()
        val eval = engine.evaluate("com.x", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-BEH-040" })
    }

    @Test
    fun `a clean app yields no concerning signals`() {
        val facts = Facts.builder()
            .text("app.package", "com.good.app")
            .bool("app.accessibility_enabled", false)
            .bool("app.has_launcher_icon", true)
            .text("app.install_source", "play")
            .build()
        val eval = engine.evaluate("com.good.app", facts)
        assertEquals(Confidence.UNLIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.concerning.isEmpty())
        assertTrue(eval.skippedRuleIds.isEmpty())
    }
}
