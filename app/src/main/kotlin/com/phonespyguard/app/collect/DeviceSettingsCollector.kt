package com.phonespyguard.app.collect

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.provider.Settings
import com.phonespyguard.detection.FactKeys
import com.phonespyguard.detection.Facts
import java.security.KeyStore

/**
 * Reads device-wide interception settings into facts for a single "device"
 * subject (FR-DEV-04, security review M2): a VPN being up, a user-added CA
 * certificate, developer options and USB debugging. The change watcher then
 * treats these like any other power, so one appearing after the baseline raises
 * the same "Did you do this?" flow.
 *
 * None of these reads need a surveillance permission: VPN presence comes from
 * the normal ACCESS_NETWORK_STATE, the rest from globally readable settings and
 * the public trust store.
 */
public class DeviceSettingsCollector(private val context: Context) {

    public fun collect(): Pair<String, Facts> {
        val facts = Facts.builder()
            .bool(FactKeys.VPN_ACTIVE, vpnActive())
            .bool(FactKeys.USER_CERTIFICATE_ADDED, userCaPresent())
            .bool(FactKeys.DEVELOPER_OPTIONS, globalFlag(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED))
            .bool(FactKeys.USB_DEBUGGING, globalFlag(Settings.Global.ADB_ENABLED))
            .build()
        return DEVICE_SUBJECT to facts
    }

    private fun vpnActive(): Boolean = runCatching {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        cm.allNetworks.any { network ->
            cm.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }.getOrDefault(false)

    private fun userCaPresent(): Boolean = runCatching {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        ks.aliases().toList().any { it.startsWith("user:") }
    }.getOrDefault(false)

    private fun globalFlag(key: String): Boolean =
        runCatching { Settings.Global.getInt(context.contentResolver, key, 0) == 1 }.getOrDefault(false)

    public companion object {
        public const val DEVICE_SUBJECT: String = "device"
    }
}
