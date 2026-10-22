package com.phonespyguard.watch

import com.phonespyguard.watch.ScreenOffTraffic.Interval
import com.phonespyguard.watch.ScreenOffTraffic.ScreenEvent
import com.phonespyguard.watch.ScreenOffTraffic.TrafficBucket
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScreenOffTrafficTest {

    @Test
    fun `off intervals are reconstructed from transitions`() {
        // window 0..100; starts interactive. Off 20..40, off 70..end.
        val events = listOf(
            ScreenEvent(20, interactive = false),
            ScreenEvent(40, interactive = true),
            ScreenEvent(70, interactive = false),
        )
        val off = ScreenOffTraffic.screenOffIntervals(events, 0, 100, initiallyInteractive = true)
        assertEquals(listOf(Interval(20, 40), Interval(70, 100)), off)
    }

    @Test
    fun `screen off at window start is counted from the start`() {
        val events = listOf(ScreenEvent(30, interactive = true))
        val off = ScreenOffTraffic.screenOffIntervals(events, 0, 100, initiallyInteractive = false)
        assertEquals(listOf(Interval(0, 30)), off)
    }

    @Test
    fun `repeated same-state events do not open spurious intervals`() {
        val events = listOf(
            ScreenEvent(10, interactive = false),
            ScreenEvent(15, interactive = false), // duplicate off
            ScreenEvent(50, interactive = true),
            ScreenEvent(55, interactive = true), // duplicate on
        )
        val off = ScreenOffTraffic.screenOffIntervals(events, 0, 100, initiallyInteractive = true)
        assertEquals(listOf(Interval(10, 50)), off)
    }

    @Test
    fun `a bucket mostly inside an off interval is attributed but a mostly-on bucket is not`() {
        val off = listOf(Interval(100, 200))
        val buckets = listOf(
            TrafficBucket(uid = 1001, startMillis = 120, endMillis = 180, bytes = 5000), // fully off
            TrafficBucket(uid = 1002, startMillis = 190, endMillis = 290, bytes = 9000), // 10 of 100 off -> no
            TrafficBucket(uid = 1001, startMillis = 150, endMillis = 250, bytes = 4000), // 50 of 100 off -> yes (>= half)
        )
        val byUid = ScreenOffTraffic.screenOffBytesByUid(buckets, off)
        assertEquals(9000L, byUid[1001]) // 5000 + 4000
        assertFalse(byUid.containsKey(1002))
    }

    @Test
    fun `no off intervals means nothing is attributed`() {
        val buckets = listOf(TrafficBucket(1001, 0, 100, 10_000))
        assertTrue(ScreenOffTraffic.screenOffBytesByUid(buckets, emptyList()).isEmpty())
    }

    @Test
    fun `the noise floor filters out small keep-alive traffic`() {
        assertFalse(ScreenOffTraffic.isSignificant(50L * 1024L))
        assertTrue(ScreenOffTraffic.isSignificant(200L * 1024L))
    }
}
