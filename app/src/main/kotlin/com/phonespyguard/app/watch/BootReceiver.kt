package com.phonespyguard.app.watch

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Re-arms the change watch after a reboot (NFR-REL-02), so watching resumes
 * without the owner having to open the app.
 */
public class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ChangeWatchScheduler.schedule(context)
        }
    }
}
