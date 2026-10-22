package com.phonespyguard.phone

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class PhoneNumberGuardTest {

    private val guard = PhoneNumberGuard()
    private val minute = 60_000L

    @Test
    fun `forwarding turning on raises one alert`() {
        val alert = guard.onForwardingIndicator(wasForwarding = false, isForwarding = true)
        assertInstanceOf(PhoneAlert.CallForwardingOn::class.java, alert)
    }

    @Test
    fun `forwarding staying on does not re-alert`() {
        assertNull(guard.onForwardingIndicator(wasForwarding = true, isForwarding = true))
    }

    @Test
    fun `forwarding turning off does not alert`() {
        assertNull(guard.onForwardingIndicator(wasForwarding = true, isForwarding = false))
    }

    @Test
    fun `sim out beyond threshold with wifi up raises a swap alarm`() {
        val start = 0L
        val alert = guard.onSimServiceState(
            simServiceLostSinceMillis = start,
            wifiConnected = true,
            nowMillis = start + 15 * minute,
        )
        val swap = assertInstanceOf(PhoneAlert.SimSwapSuspected::class.java, alert)
        assertEquals(15 * minute, swap.outageMillis)
    }

    @Test
    fun `sim out but within threshold does not alarm`() {
        assertNull(
            guard.onSimServiceState(
                simServiceLostSinceMillis = 0L,
                wifiConnected = true,
                nowMillis = 9 * minute,
            ),
        )
    }

    @Test
    fun `sim out with wifi also down does not alarm (likely no coverage)`() {
        assertNull(
            guard.onSimServiceState(
                simServiceLostSinceMillis = 0L,
                wifiConnected = false,
                nowMillis = 60 * minute,
            ),
        )
    }

    @Test
    fun `sim with service does not alarm`() {
        assertNull(
            guard.onSimServiceState(
                simServiceLostSinceMillis = null,
                wifiConnected = true,
                nowMillis = 60 * minute,
            ),
        )
    }
}
