package com.phonespyguard.watch

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class WatchGapDetectorTest {

    private val minute = 60_000L
    private val detector = WatchGapDetector() // 15 min interval, 5 min tolerance

    @Test
    fun `a normal cadence is not a gap`() {
        assertNull(detector.check(lastRunMillis = 0 + minute, nowMillis = minute + 15 * minute))
    }

    @Test
    fun `within tolerance is not a gap`() {
        assertNull(detector.check(lastRunMillis = minute, nowMillis = minute + 19 * minute))
    }

    @Test
    fun `a long gap is reported`() {
        val gap = detector.check(lastRunMillis = minute, nowMillis = minute + 90 * minute)
        assertNotNull(gap)
        assertEquals(90 * minute, gap!!.durationMillis)
    }

    @Test
    fun `the first run has no baseline`() {
        assertNull(detector.check(lastRunMillis = 0, nowMillis = 100 * minute))
    }
}
