package com.phonespyguard.app.collect

import android.app.AppOpsManager
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import com.phonespyguard.watch.ScreenOffTraffic
import com.phonespyguard.watch.ScreenOffTraffic.ScreenEvent
import com.phonespyguard.watch.ScreenOffTraffic.TrafficBucket

/**
 * Measures how many bytes each app *sent* while the screen was off, over the
 * last [windowMillis] (market-scan item 6). This is the signal behind
 * "an app that uploads while your screen is off": a monitoring app keeps
 * exfiltrating when you are not using the phone.
 *
 * It needs **usage access**, a special permission the owner grants by hand in
 * Settings — the app never holds it silently. Without the grant this collector
 * returns an empty map and the signal is simply off (it never guesses). The
 * grant lets the system [NetworkStatsManager] report other apps' totals and the
 * [UsageStatsManager] report screen on/off transitions; the actual reasoning
 * lives in the pure [ScreenOffTraffic] analyser so it is unit-tested off-device.
 *
 * Only bytes *transmitted* (uploaded) are counted, and the window start is
 * treated as screen-on, so the estimate under-counts rather than over-accuses.
 */
public class ScreenOffTrafficCollector(
    private val context: Context,
    private val windowMillis: Long = 24L * 60L * 60L * 1000L,
) {

    /** Screen-off uploaded bytes per package, empty when usage access is not granted. */
    public fun collect(now: Long = System.currentTimeMillis()): Map<String, Long> {
        if (!hasUsageAccess()) return emptyMap()
        val start = now - windowMillis
        val offIntervals = runCatching { screenOffIntervals(start, now) }.getOrNull() ?: return emptyMap()
        if (offIntervals.isEmpty()) return emptyMap()

        val buckets = runCatching { trafficBuckets(start, now) }.getOrNull() ?: return emptyMap()
        val byUid = ScreenOffTraffic.screenOffBytesByUid(buckets, offIntervals)

        val byPackage = HashMap<String, Long>()
        val pm = context.packageManager
        for ((uid, bytes) in byUid) {
            if (uid == Process.SYSTEM_UID || uid == Process.myUid()) continue
            val packages = pm.getPackagesForUid(uid) ?: continue
            // A shared uid can back more than one package; attribute to each, as
            // any of them could be the sender (the rule still needs a concerning
            // trait before this becomes a strong signal).
            for (pkg in packages) byPackage[pkg] = maxOf(byPackage[pkg] ?: 0L, bytes)
        }
        return byPackage
    }

    private fun screenOffIntervals(start: Long, end: Long): List<ScreenOffTraffic.Interval> {
        val usage = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return emptyList()
        val events = usage.queryEvents(start, end)
        val transitions = mutableListOf<ScreenEvent>()
        val event = UsageEvents.Event()
        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            when (event.eventType) {
                UsageEvents.Event.SCREEN_INTERACTIVE ->
                    transitions += ScreenEvent(event.timeStamp, interactive = true)
                UsageEvents.Event.SCREEN_NON_INTERACTIVE ->
                    transitions += ScreenEvent(event.timeStamp, interactive = false)
            }
        }
        // Window start is treated as screen-on, so an unseen earlier off-period
        // is not counted — the estimate under-counts rather than over-accuses.
        return ScreenOffTraffic.screenOffIntervals(transitions, start, end, initiallyInteractive = true)
    }

    private fun trafficBuckets(start: Long, end: Long): List<TrafficBucket> {
        val nsm = context.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager
            ?: return emptyList()
        val buckets = mutableListOf<TrafficBucket>()
        for (networkType in intArrayOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            // subscriberId is null: no telephony identity is read, so this needs
            // no READ_PHONE_STATE — usage access alone authorises the query.
            val stats = runCatching { nsm.queryDetails(networkType, null, start, end) }.getOrNull() ?: continue
            val bucket = android.app.usage.NetworkStats.Bucket()
            try {
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(bucket)
                    // Count uploaded bytes only — that is the exfiltration signal.
                    buckets += TrafficBucket(
                        uid = bucket.uid,
                        startMillis = bucket.startTimeStamp,
                        endMillis = bucket.endTimeStamp,
                        bytes = bucket.txBytes,
                    )
                }
            } finally {
                stats.close()
            }
        }
        return buckets
    }

    /** Whether the owner has granted usage access to this app. */
    public fun hasUsageAccess(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName,
                )
            } else {
                // unsafeCheckOpNoThrow is API 29+; on Android 9 it would throw
                // and usage access would always read as off.
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName,
                )
            }
        }.getOrDefault(AppOpsManager.MODE_DEFAULT)
        return mode == AppOpsManager.MODE_ALLOWED
    }
}
