package com.phonespyguard.app.watch

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.phonespyguard.app.AppSettings

/**
 * Raises change-watch alerts — carefully, because a notification is the one
 * thing that can leak straight to the abuser (security review H1).
 *
 * Stalkerware usually holds notification access, so any notification this app
 * posts could be read and forwarded. Therefore alerts are:
 *  - **off unless the owner opted in** ([AppSettings.alertsEnabled]);
 *  - **suppressed entirely while any other app holds notification access**, so a
 *    watcher never learns a scan found something — the finding waits inside the
 *    app instead;
 *  - **neutral**: a plain channel name and text that say nothing about spyware.
 */
public class AlertNotifier(private val context: Context) {

    private val settings = AppSettings(context)

    public fun ensureChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            // Neutral channel name — nothing that hints at spyware (H1).
            "Sync",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Background sync status"
            setShowBadge(false)
        }
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    /** Post at most one neutral, detail-free alert, if it is safe and opted in. */
    public fun notifyFindingsWaiting() {
        if (!settings.alertsEnabled) return
        if (!hasPostPermission()) return
        // If anything on the phone can read notifications, don't post at all —
        // the finding would reach the watcher. It waits inside the app.
        if (anyNotificationListenerPresent()) return

        ensureChannel()
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setContentTitle("Sync complete")
            .setContentText("Open the app when you have a private moment.")
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(context).notify(FIXED_ID, notification)
    }

    /** True if any app holds notification-listener access (so could read alerts). */
    private fun anyNotificationListenerPresent(): Boolean {
        val value = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
        return !value.isNullOrBlank()
    }

    private fun hasPostPermission(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private companion object {
        const val CHANNEL_ID = "psg_sync"

        // A single fixed id: findings are reviewed in-app, so alerts never need
        // to be per-subject, and can't overwrite each other (security review L2).
        const val FIXED_ID = 1
    }
}
