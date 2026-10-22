package com.phonespyguard.phone

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ForwardingCodesTest {

    @Test
    fun `interrogate deactivate and erase codes for a condition`() {
        assertEquals("*#67#", ForwardingCodes.build(ForwardingType.BUSY, MmiAction.INTERROGATE).code)
        assertEquals("#67#", ForwardingCodes.build(ForwardingType.BUSY, MmiAction.DEACTIVATE).code)
        assertEquals("##67#", ForwardingCodes.build(ForwardingType.BUSY, MmiAction.ERASE).code)
    }

    @Test
    fun `register builds the number code`() {
        val c = ForwardingCodes.build(ForwardingType.UNCONDITIONAL, MmiAction.REGISTER, "+15551234")
        assertEquals("**21*+15551234#", c.code)
        assertTrue(c.explanation.contains("+15551234"))
    }

    @Test
    fun `register requires a number`() {
        assertThrows(IllegalArgumentException::class.java) {
            ForwardingCodes.build(ForwardingType.UNCONDITIONAL, MmiAction.REGISTER, null)
        }
    }

    @Test
    fun `cannot register against the all aggregates`() {
        assertThrows(IllegalArgumentException::class.java) {
            ForwardingCodes.build(ForwardingType.ALL, MmiAction.REGISTER, "+15551234")
        }
    }

    @Test
    fun `check all and cancel all shortcuts`() {
        assertEquals("*#002#", ForwardingCodes.checkAll().code)
        assertEquals("##002#", ForwardingCodes.cancelAll().code)
    }

    @Test
    fun `conditional cancels cover busy no-reply and unreachable`() {
        val codes = ForwardingCodes.conditionalCancels().map { it.code }
        assertEquals(listOf("##67#", "##61#", "##62#"), codes)
    }
}
