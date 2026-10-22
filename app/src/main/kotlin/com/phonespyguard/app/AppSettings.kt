package com.phonespyguard.app

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

/**
 * The owner's safety-relevant preferences, and the actions that depend on them.
 *
 * - Alerts are **off by default** (security review H1): a notification can be
 *   read by stalkerware holding notification access, so the owner opts in.
 * - The discreet launcher swaps the app's name and icon for a neutral one
 *   (FR-SAF-05) by toggling the two activity-aliases.
 * - The last watch-run time backs watch-gap detection (FR-WCH-04).
 */
public class AppSettings(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("psg_settings", Context.MODE_PRIVATE)

    public var alertsEnabled: Boolean
        get() = prefs.getBoolean(KEY_ALERTS, false)
        set(value) = prefs.edit().putBoolean(KEY_ALERTS, value).apply()

    public var lastRunMillis: Long
        get() = prefs.getLong(KEY_LAST_RUN, 0L)
        set(value) = prefs.edit().putLong(KEY_LAST_RUN, value).apply()

    public val discreetMode: Boolean
        get() = aliasEnabled(DISCREET_ALIAS)

    /** Switch between the real-name and neutral launcher icon/label (FR-SAF-05). */
    public fun setDiscreetMode(discreet: Boolean) {
        enableAlias(DISCREET_ALIAS, discreet)
        enableAlias(DEFAULT_ALIAS, !discreet)
    }

    private fun aliasEnabled(alias: String): Boolean {
        val state = appContext.packageManager.getComponentEnabledSetting(
            ComponentName(appContext, alias),
        )
        return state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    }

    private fun enableAlias(alias: String, enabled: Boolean) {
        val newState = if (enabled) {
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        } else {
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        }
        appContext.packageManager.setComponentEnabledSetting(
            ComponentName(appContext, alias),
            newState,
            PackageManager.DONT_KILL_APP,
        )
    }

    private companion object {
        const val KEY_ALERTS = "alerts_enabled"
        const val KEY_LAST_RUN = "last_run_millis"
        const val DEFAULT_ALIAS = "com.phonespyguard.app.Launcher"
        const val DISCREET_ALIAS = "com.phonespyguard.app.LauncherDiscreet"
    }
}
