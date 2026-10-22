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
    fun `an APK whose file hash matches a sample is confirmed (item 4)`() {
        val facts = Facts.builder()
            .text("app.package", "com.renamed.helper")
            .bool("app.known_stalkerware_file_match", true)
            .build()
        val eval = engine.evaluate("com.renamed.helper", facts)
        assertEquals(Confidence.CONFIRMED, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-KNOWN-003" })
    }

    @Test
    fun `a known watchware product is possible (item 4)`() {
        val facts = Facts.builder()
            .text("app.package", "com.wondershare.famisafe")
            .bool("app.watchware_match", true)
            .build()
        val eval = engine.evaluate("com.wondershare.famisafe", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-060" })
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
    fun `an app disguised as a system component is very likely (item 5)`() {
        val facts = Facts.builder()
            .text("app.package", "com.android.systemservice")
            .bool("app.poses_as_system", true)
            .build()
        val eval = engine.evaluate("com.android.systemservice", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-BEH-060" })
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
    fun `a hidden app granted three surveillance permission groups is very likely (item 3)`() {
        // No icon, not a system app, and granted microphone + camera + location.
        // None of the four special-access powers are held, so this is caught only
        // because the engine now scores the granted dangerous permissions.
        val facts = Facts.builder()
            .text("app.package", "com.sneaky.recorder")
            .bool("app.has_launcher_icon", false)
            .bool("app.is_system_app", false)
            .textList("app.granted_surveillance_permissions", listOf("microphone", "camera", "location"))
            .number("app.granted_surveillance_permission_count", 3)
            .number("app.surveillance_power_count", 0)
            .build()
        val eval = engine.evaluate("com.sneaky.recorder", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-BEH-050" })
    }

    @Test
    fun `a sideloaded app granted three surveillance permission groups is possible (item 3)`() {
        val facts = Facts.builder()
            .text("app.package", "com.side.load")
            .text("app.install_source", "sideload")
            .bool("app.is_system_app", false)
            .bool("app.has_launcher_icon", true)
            .textList("app.granted_surveillance_permissions", listOf("sms", "contacts", "location"))
            .number("app.granted_surveillance_permission_count", 3)
            .build()
        val eval = engine.evaluate("com.side.load", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-050" })
    }

    @Test
    fun `an app reading texts and call history but not the sms app is possible (item 3)`() {
        val facts = Facts.builder()
            .text("app.package", "com.reads.both")
            .bool("app.is_system_app", false)
            .bool("app.default_sms", false)
            .textList("app.granted_surveillance_permissions", listOf("sms", "call_log"))
            .number("app.granted_surveillance_permission_count", 2)
            .build()
        val eval = engine.evaluate("com.reads.both", facts)
        assertEquals(Confidence.POSSIBLE, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-RISK-051" })
    }

    @Test
    fun `a mainstream store app with camera mic and location is not flagged (item 3)`() {
        // A chat app from the store legitimately holds camera, microphone and
        // location. Because it is store-installed and visible, the broad-access
        // rules must not fire — scoring granted permissions must not turn into
        // flagging every social app.
        val facts = Facts.builder()
            .text("app.package", "com.popular.chat")
            .text("app.install_source", "play")
            .bool("app.is_system_app", false)
            .bool("app.has_launcher_icon", true)
            .bool("app.default_sms", false)
            .textList("app.granted_surveillance_permissions", listOf("camera", "microphone", "location"))
            .number("app.granted_surveillance_permission_count", 3)
            .build()
        val eval = engine.evaluate("com.popular.chat", facts)
        assertEquals(Confidence.UNLIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.concerning.isEmpty())
    }

    @Test
    fun `a watchware app that uploads while screen off is elevated to very likely (item 6)`() {
        // Watchware alone is only "Possible"; uploading while the screen is off
        // elevates it — a monitoring product quietly reporting back.
        val facts = Facts.builder()
            .text("app.package", "com.wondershare.famisafe")
            .bool("app.watchware_match", true)
            .bool("app.uploads_screen_off", true)
            .build()
        val eval = engine.evaluate("com.wondershare.famisafe", facts)
        assertEquals(Confidence.VERY_LIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.signals.any { it.ruleId == "PSG-BEH-022" })
    }

    @Test
    fun `a visible store app uploading while screen off is not flagged (item 6)`() {
        // Background sync from a normal store app you can see must not be a strong
        // signal — the screen-off upload needs a concerning companion trait.
        val facts = Facts.builder()
            .text("app.package", "com.popular.mail")
            .text("app.install_source", "play")
            .bool("app.is_system_app", false)
            .bool("app.has_launcher_icon", true)
            .bool("app.uploads_screen_off", true)
            .number("app.granted_surveillance_permission_count", 1)
            .build()
        val eval = engine.evaluate("com.popular.mail", facts)
        assertEquals(Confidence.UNLIKELY, eval.verdict.confidence)
        assertTrue(eval.verdict.concerning.isEmpty())
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
