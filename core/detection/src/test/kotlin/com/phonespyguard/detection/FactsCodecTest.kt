package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class FactsCodecTest {

    @Test
    fun `facts round-trip through json preserving types`() {
        val facts = Facts.builder()
            .text("app.package", "com.x")
            .bool("app.accessibility_enabled", true)
            .number("app.install_time", 1_700_000_000_000L)
            .textList("app.permissions", listOf("CAMERA", "RECORD_AUDIO"))
            .build()

        val decoded = FactsCodec.decode(FactsCodec.encode(facts))

        assertEquals(FactValue.Text("com.x"), decoded["app.package"])
        assertEquals(FactValue.Bool(true), decoded["app.accessibility_enabled"])
        assertEquals(FactValue.Number(1_700_000_000_000L), decoded["app.install_time"])
        assertEquals(FactValue.TextList(listOf("CAMERA", "RECORD_AUDIO")), decoded["app.permissions"])
    }

    @Test
    fun `snapshot round-trips`() {
        val snapshot = mapOf(
            "com.a" to Facts.builder().bool("app.device_admin", true).build(),
            "com.b" to Facts.builder().text("app.install_source", "sideload").build(),
        )
        val restored = FactsCodec.decodeSnapshot(FactsCodec.encodeSnapshot(snapshot))

        assertEquals(2, restored.size)
        assertEquals(FactValue.Bool(true), restored.getValue("com.a")["app.device_admin"])
        assertEquals(FactValue.Text("sideload"), restored.getValue("com.b")["app.install_source"])
    }
}
