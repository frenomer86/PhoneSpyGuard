package com.phonespyguard.watch

import com.phonespyguard.detection.FactKeys
import com.phonespyguard.detection.Facts
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChangeDetectorTest {

    private val detector = ChangeDetector()

    private fun app(
        source: String = "play",
        icon: Boolean = true,
        accessibility: Boolean = false,
        deviceAdmin: Boolean = false,
    ): Facts = Facts.builder()
        .text(FactKeys.INSTALL_SOURCE, source)
        .bool(FactKeys.HAS_LAUNCHER_ICON, icon)
        .bool(FactKeys.ACCESSIBILITY_ENABLED, accessibility)
        .bool(FactKeys.DEVICE_ADMIN, deviceAdmin)
        .build()

    @Test
    fun `no change yields no events`() {
        val snap = mapOf("com.a" to app())
        assertTrue(detector.diff(snap, snap).isEmpty())
    }

    @Test
    fun `a signing-certificate change on update is concerning (M2)`() {
        val before = mapOf(
            "com.a" to Facts.builder()
                .text(FactKeys.INSTALL_SOURCE, "play")
                .bool(FactKeys.HAS_LAUNCHER_ICON, true)
                .text(FactKeys.CERT_SHA256, "aaaa")
                .build(),
        )
        val after = mapOf(
            "com.a" to Facts.builder()
                .text(FactKeys.INSTALL_SOURCE, "play")
                .bool(FactKeys.HAS_LAUNCHER_ICON, true)
                .text(FactKeys.CERT_SHA256, "bbbb")
                .build(),
        )
        val e = detector.diff(before, after).single { it.kind == ChangeKind.CERT_CHANGED }
        assertTrue(e.concerning)
    }

    @Test
    fun `a new sideloaded app is concerning`() {
        val events = detector.diff(emptyMap(), mapOf("com.x" to app(source = "sideload")))
        val e = events.single { it.kind == ChangeKind.NEW_SIDELOADED_APP }
        assertTrue(e.concerning)
    }

    @Test
    fun `a new play-store app is not concerning on its own`() {
        val events = detector.diff(emptyMap(), mapOf("com.x" to app(source = "play")))
        val e = events.single { it.kind == ChangeKind.NEW_APP }
        assertFalse(e.concerning)
    }

    @Test
    fun `gaining accessibility is flagged`() {
        val old = mapOf("com.x" to app(accessibility = false))
        val new = mapOf("com.x" to app(accessibility = true))
        val e = detector.diff(old, new).single { it.kind == ChangeKind.GAINED_POWER }
        assertEquals(FactKeys.ACCESSIBILITY_ENABLED, e.factKey)
        assertTrue(e.concerning)
    }

    @Test
    fun `gaining device admin is flagged separately`() {
        val old = mapOf("com.x" to app(deviceAdmin = false))
        val new = mapOf("com.x" to app(deviceAdmin = true))
        val powers = detector.diff(old, new).filter { it.kind == ChangeKind.GAINED_POWER }
        assertEquals(1, powers.size)
        assertEquals(FactKeys.DEVICE_ADMIN, powers.single().factKey)
    }

    @Test
    fun `hiding the launcher icon is flagged`() {
        val old = mapOf("com.x" to app(icon = true))
        val new = mapOf("com.x" to app(icon = false))
        val e = detector.diff(old, new).single { it.kind == ChangeKind.HID_ICON }
        assertTrue(e.concerning)
    }

    @Test
    fun `a new app that already holds a power flags both`() {
        val new = mapOf("com.x" to app(source = "sideload", accessibility = true))
        val events = detector.diff(emptyMap(), new)
        assertTrue(events.any { it.kind == ChangeKind.NEW_SIDELOADED_APP })
        assertTrue(events.any { it.kind == ChangeKind.GAINED_POWER })
    }

    @Test
    fun `a removed app is reported but not concerning`() {
        val old = mapOf("com.x" to app())
        val e = detector.diff(old, emptyMap()).single()
        assertEquals(ChangeKind.REMOVED_APP, e.kind)
        assertFalse(e.concerning)
    }
}
