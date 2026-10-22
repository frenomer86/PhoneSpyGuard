package com.phonespyguard.watch

/**
 * Pure analysis behind the "sends data while your screen is off" signal
 * (market-scan item 6). A monitoring app's tell is that it keeps uploading when
 * you are not using the phone; a normal app's network use mostly tracks your
 * own activity. On Android the raw numbers come from the system
 * `NetworkStatsManager` and `UsageStatsManager` — which the owner must grant
 * usage access for — but the reasoning is kept here, in pure JVM code, so it is
 * unit-tested off-device and shares one definition with the desktop core.
 */
public object ScreenOffTraffic {

    /** Default floor below which screen-off bytes are treated as keep-alive noise. */
    public const val DEFAULT_THRESHOLD_BYTES: Long = 100L * 1024L

    /** A screen on/off transition, as read from the usage-event stream. */
    public data class ScreenEvent(val atMillis: Long, val interactive: Boolean)

    /** Bytes one app (by Linux uid) transferred over one time bucket. */
    public data class TrafficBucket(
        val uid: Int,
        val startMillis: Long,
        val endMillis: Long,
        val bytes: Long,
    )

    /** A half-open time interval `[startMillis, endMillis)`. */
    public data class Interval(val startMillis: Long, val endMillis: Long) {
        public val durationMillis: Long get() = (endMillis - startMillis).coerceAtLeast(0)
    }

    /**
     * Reconstructs the screen-off intervals inside `[windowStart, windowEnd)`
     * from the transition events. [initiallyInteractive] is the screen state at
     * [windowStart] (before the first event in range). Events are sorted and
     * clamped to the window; a run of same-state events collapses, so only real
     * transitions open or close an interval.
     */
    public fun screenOffIntervals(
        events: List<ScreenEvent>,
        windowStart: Long,
        windowEnd: Long,
        initiallyInteractive: Boolean,
    ): List<Interval> {
        if (windowEnd <= windowStart) return emptyList()
        val sorted = events.filter { it.atMillis in windowStart until windowEnd }
            .sortedBy { it.atMillis }
        val intervals = mutableListOf<Interval>()
        var interactive = initiallyInteractive
        var offSince = if (!initiallyInteractive) windowStart else -1L
        for (e in sorted) {
            if (e.interactive == interactive) continue // no real change
            interactive = e.interactive
            if (!interactive) {
                offSince = e.atMillis // screen just went off
            } else if (offSince >= 0) {
                if (e.atMillis > offSince) intervals += Interval(offSince, e.atMillis)
                offSince = -1L
            }
        }
        // Still off at the end of the window.
        if (!interactive && offSince in windowStart until windowEnd) {
            intervals += Interval(offSince, windowEnd)
        }
        return intervals
    }

    /**
     * Sums, per uid, the bytes from buckets that fall predominantly within a
     * screen-off interval. A bucket counts only when at least half of its
     * duration overlaps the off intervals, so a bucket that mostly spans screen-
     * on time is not misattributed. A zero-duration bucket counts only if its
     * instant lies inside an off interval.
     */
    public fun screenOffBytesByUid(
        buckets: List<TrafficBucket>,
        offIntervals: List<Interval>,
    ): Map<Int, Long> {
        if (offIntervals.isEmpty()) return emptyMap()
        val byUid = HashMap<Int, Long>()
        for (b in buckets) {
            if (b.bytes <= 0) continue
            val overlap = offIntervals.sumOf { overlapMillis(b.startMillis, b.endMillis, it) }
            val duration = (b.endMillis - b.startMillis).coerceAtLeast(0)
            val counts = if (duration == 0L) {
                offIntervals.any { b.startMillis >= it.startMillis && b.startMillis < it.endMillis }
            } else {
                overlap * 2 >= duration
            }
            if (counts) byUid[b.uid] = (byUid[b.uid] ?: 0L) + b.bytes
        }
        return byUid
    }

    /** True when the uid's screen-off bytes clear the noise floor. */
    public fun isSignificant(
        screenOffBytes: Long,
        thresholdBytes: Long = DEFAULT_THRESHOLD_BYTES,
    ): Boolean = screenOffBytes >= thresholdBytes

    private fun overlapMillis(start: Long, end: Long, interval: Interval): Long {
        val lo = maxOf(start, interval.startMillis)
        val hi = minOf(end, interval.endMillis)
        return (hi - lo).coerceAtLeast(0)
    }
}
