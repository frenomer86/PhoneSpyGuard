package com.phonespyguard.watch

/**
 * Detects periods during which the change watch was not running (FR-WCH-04,
 * NFR-SEC-10).
 *
 * The watcher is scheduled to run on a fixed cadence (every 15 minutes). If it
 * was force-stopped, disabled, or starved by a battery restriction, the gap
 * between two recorded run times exceeds that cadence by a margin. A gap is not
 * an accusation on its own, but it is recorded so the timeline never silently
 * hides a blind spot — stalkerware commonly tries to stop the watchdog.
 */
public class WatchGapDetector(
    private val expectedIntervalMillis: Long = 15 * 60 * 1000,
    /** How far past the expected interval counts as a real gap, not jitter. */
    private val toleranceMillis: Long = 5 * 60 * 1000,
) {
    public data class Gap(val fromMillis: Long, val toMillis: Long) {
        val durationMillis: Long get() = toMillis - fromMillis
    }

    /**
     * Given the last time the watcher ran and the time it is running now,
     * return a [Gap] if the gap is longer than one interval plus tolerance.
     */
    public fun check(lastRunMillis: Long, nowMillis: Long): Gap? {
        if (lastRunMillis <= 0) return null // first run, no baseline to compare
        val gap = nowMillis - lastRunMillis
        return if (gap > expectedIntervalMillis + toleranceMillis) {
            Gap(lastRunMillis, nowMillis)
        } else {
            null
        }
    }
}
