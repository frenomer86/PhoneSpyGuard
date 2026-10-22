package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class IndicatorSetTest {

    private val set = IndicatorSet(
        stalkerware = listOf(
            AppIndicator("com.evil.track", certSha1 = "aa11", name = "EvilTrack"),
            AppIndicator("com.android.systemservice", name = "Disguised service"),
            // A cert-only known-bad entry: catches a renamed sample signed by the same key.
            AppIndicator(certSha1 = "cc33", name = "Operator key"),
        ),
        screenReaders = listOf(AppIndicator("com.google.android.marvin.talkback", name = "TalkBack")),
        parentalControl = listOf(AppIndicator("com.qustodio.qustodioapp", name = "Qustodio")),
        knownGoodKeyboards = listOf(AppIndicator("com.google.android.inputmethod.latin", name = "Gboard")),
    )

    @Test
    fun `package-only known-bad matches regardless of cert`() {
        val c = set.classify("com.android.systemservice", certSha1 = null, isSystemApp = false)
        assertTrue(c.knownStalkerware)
        assertEquals("Disguised service", c.stalkerwareName)
    }

    @Test
    fun `known-bad matches on package OR cert`() {
        // package match, any cert
        assertTrue(set.classify("com.evil.track", " zz ".trim(), isSystemApp = false).knownStalkerware)
        // renamed package but operator's cert is pinned -> still caught (C1)
        assertTrue(set.classify("com.freshly.renamed", "CC33", isSystemApp = true).knownStalkerware)
        // unrelated package and cert -> clear
        assertFalse(set.classify("com.freshly.renamed", "dd44", isSystemApp = true).knownStalkerware)
    }

    @Test
    fun `unknown package is not flagged`() {
        val c = set.classify("com.good.app", null, isSystemApp = true)
        assertFalse(c.knownStalkerware)
        assertNull(c.stalkerwareName)
        assertFalse(c.isScreenReader)
    }

    @Test
    fun `an unpinned allow-list entry is honoured only for a genuine system app (N2)`() {
        // A real pre-installed (system-partition) TalkBack is honoured.
        assertTrue(set.classify("com.google.android.marvin.talkback", null, isSystemApp = true).isScreenReader)
        // A sideloaded impostor borrowing the name is NOT honoured.
        assertFalse(set.classify("com.google.android.marvin.talkback", null, isSystemApp = false).isScreenReader)
        // Same rule for keyboards and parental control.
        assertTrue(set.classify("com.google.android.inputmethod.latin", null, isSystemApp = true).isKnownGoodKeyboard)
        assertFalse(set.classify("com.google.android.inputmethod.latin", null, isSystemApp = false).isKnownGoodKeyboard)
        assertTrue(set.classify("com.qustodio.qustodioapp", null, isSystemApp = true).isParentalControl)
        assertFalse(set.classify("com.qustodio.qustodioapp", null, isSystemApp = false).isParentalControl)
    }

    @Test
    fun `a spoofed Play install source cannot excuse an app`() {
        // The collector only ever passes isSystemApp=false for a non-system app,
        // no matter what installer the app claims (adb install -i com.android.
        // vending). So an impostor that faked a Play install is still NOT
        // excused — the install source is never consulted here (round-3 finding).
        assertFalse(set.classify("com.google.android.marvin.talkback", null, isSystemApp = false).isScreenReader)
    }

    @Test
    fun `a cert-pinned allow-list entry needs the matching cert`() {
        val pinned = IndicatorSet(
            screenReaders = listOf(AppIndicator("com.reader", certSha1 = "ab12", name = "Reader")),
        )
        // Pinned cert matches even for a non-system app.
        assertTrue(pinned.classify("com.reader", "AB12", isSystemApp = false).isScreenReader)
        // Wrong cert never passes, even for a system app.
        assertFalse(pinned.classify("com.reader", "ffff", isSystemApp = true).isScreenReader)
        // No cert presented, pin set, not system -> not excused.
        assertFalse(pinned.classify("com.reader", null, isSystemApp = false).isScreenReader)
    }

    @Test
    fun `an APK file-hash match is a confirmed sample regardless of package or cert (item 4)`() {
        val hashed = IndicatorSet(
            fileHashes = setOf("2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7"),
        )
        // The sample hash matches even though the package is unknown and renamed.
        assertTrue(
            hashed.classify(
                "com.freshly.renamed",
                certSha1 = null,
                isSystemApp = false,
                fileSha256 = "2F3BC9EBE8C249F0416F5B0367F34B4B8F6AAA7D351DC5B4912FE2558491B6B7",
            ).knownStalkerwareFile,
        )
        // A different hash, or none, is not a file match.
        assertFalse(hashed.classify("com.x", null, false, fileSha256 = "deadbeef").knownStalkerwareFile)
        assertFalse(hashed.classify("com.x", null, false, fileSha256 = null).knownStalkerwareFile)
    }

    @Test
    fun `watchware matches on package or cert and carries the product name (item 4)`() {
        val ww = IndicatorSet(
            watchware = listOf(
                AppIndicator("com.wondershare.famisafe", name = "FamiSafe"),
                AppIndicator(certSha1 = "ee55", name = "WiseMo"),
            ),
        )
        val byPkg = ww.classify("com.wondershare.famisafe", null, isSystemApp = false)
        assertTrue(byPkg.watchwareMatch)
        assertEquals("FamiSafe", byPkg.watchwareName)
        assertTrue(ww.classify("com.renamed", "EE55", isSystemApp = false).watchwareMatch)
        assertFalse(ww.classify("com.unrelated", "ffff", isSystemApp = false).watchwareMatch)
    }

    @Test
    fun `C2 matching is case-insensitive on domains and exact on IPs (item 4)`() {
        val net = NetworkIndicators(domains = setOf("panel24.org"), ips = setOf("203.0.113.9"))
        assertTrue(net.matches("Panel24.org"))
        assertTrue(net.matches("203.0.113.9"))
        assertFalse(net.matches("example.com"))
        assertFalse(net.matches(""))
    }

    @Test
    fun `parsed from the shipped bundle`() {
        val text = requireNotNull(javaClass.getResourceAsStream("/rules/launch-bundle.json"))
            .readBytes().toString(Charsets.UTF_8)
        val bundle = RuleBundleParser().parse(text)
        // A real Echap stalkerware package (Cerberus).
        assertTrue(bundle.indicators.classify("com.lsdroid.cerberus", null, isSystemApp = false).knownStalkerware)
        // A mercenary app id from the MVT RCS Lab set.
        assertTrue(bundle.indicators.classify("com.androidservices.support", null, isSystemApp = false).mercenaryMatch)
        // Screen reader from the allow-list, honoured for a system install.
        assertTrue(bundle.indicators.classify("com.google.android.marvin.talkback", null, isSystemApp = true).isScreenReader)
        // The bundle ships the real dataset, not a 5-name stub.
        assertTrue(bundle.indicators.stalkerware.size > 200, "expected the full Echap set")
    }
}
