package com.phonespyguard.app.watch

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Triggers an immediate change-watch scan when an app is installed or replaced
 * (market-scan item 5), so a freshly planted app is examined within moments
 * rather than at the next 15-minute tick.
 *
 * Registered in the manifest for `PACKAGE_ADDED` / `PACKAGE_REPLACED` with the
 * `package` data scheme. The app's own replacement is ignored (that is handled
 * by the boot/update path), and a replacement that is really an update — the
 * `EXTRA_REPLACING` flag on the paired `PACKAGE_REMOVED` — still fires a scan,
 * because a certificate change on update is itself something the watch reports.
 * Where a device throttles this broadcast, the periodic watch remains the
 * guaranteed path; this only improves latency when the broadcast is delivered.
 */
public class PackageChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_PACKAGE_ADDED, Intent.ACTION_PACKAGE_REPLACED -> {
                val changed = intent.data?.schemeSpecificPart
                // The app seeing its own install/replace is not an external change.
                if (changed == context.packageName) return
                ChangeWatchScheduler.scanNow(context)
            }
        }
    }
}
