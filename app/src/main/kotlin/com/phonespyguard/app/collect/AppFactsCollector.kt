package com.phonespyguard.app.collect

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PackageInstaller
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.telecom.TelecomManager
import android.view.inputmethod.InputMethodManager
import com.phonespyguard.detection.FactKeys
import com.phonespyguard.detection.Facts
import com.phonespyguard.detection.IndicatorSet
import com.phonespyguard.watch.Snapshot
import java.security.MessageDigest

/**
 * Reads the installed apps into [Facts] for the detection engine (FR-DEV).
 *
 * The surveillance-grade powers an app holds — accessibility, device-admin,
 * notification access, the default SMS/dialer role — are read from globally
 * readable system settings, so this app can see *which other apps* hold them
 * without holding any of them itself.
 *
 * Identity facts (`known_stalkerware_match`, `is_screen_reader`, …) are set by
 * matching the app's package and signing certificate against [indicators], the
 * signed indicator set carried in the verified rule bundle (security review C1,
 * H2). Nothing is trusted from what the app says about itself.
 */
public class AppFactsCollector(
    private val context: Context,
    private val indicators: IndicatorSet = IndicatorSet(),
) {

    private val pm: PackageManager = context.packageManager

    /**
     * @param priorCerts the signing-cert hash seen for each package at the last
     *   scan, used to flag a certificate change on update (security review M2).
     * @param screenOffBytes bytes each package uploaded while the screen was off,
     *   from [ScreenOffTrafficCollector] when the owner has granted usage access;
     *   empty otherwise, which leaves the screen-off signal off (market-scan item 6).
     */
    public fun collect(
        priorCerts: Map<String, String> = emptyMap(),
        screenOffBytes: Map<String, Long> = emptyMap(),
    ): Snapshot {
        val accessibilityPkgs = enabledComponentPackages(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        val notificationPkgs = enabledComponentPackages("enabled_notification_listeners")
        val adminPkgs = activeDeviceAdminPackages()
        val keyboardPkgs = enabledInputMethodPackages()
        val defaultSms = Telephony.Sms.getDefaultSmsPackage(context)
        val defaultDialer = context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage

        val installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        val snapshot = HashMap<String, Facts>(installed.size)

        for (info in installed) {
            val pkg = info.packageName
            val appInfo = info.applicationInfo
            val isSystem = appInfo != null && (
                appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0 ||
                    appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
                )
            val requested = info.requestedPermissions?.toSet().orEmpty()
            val grantedGroups = grantedSurveillanceGroups(info)
            val certBytes = signingCertBytes(pkg)
            val cert = certBytes?.let { hash(it, "SHA-256") }
            val certSha1 = certBytes?.let { hash(it, "SHA-1") }

            val hasAccessibility = pkg in accessibilityPkgs
            val hasAdmin = pkg in adminPkgs
            val hasNotif = pkg in notificationPkgs
            val isDefaultSms = pkg == defaultSms
            val powerCount = listOf(hasAccessibility, hasAdmin, hasNotif, isDefaultSms).count { it }

            val source = installSource(pkg, isSystem)
            // A benign allow-list match (screen reader, keyboard, parental) is
            // only honoured when the app is *provably* that app: it presents the
            // pinned certificate, or it is a genuine system-partition app. The
            // install source is deliberately NOT used to excuse an app, because
            // `adb install -i com.android.vending` fakes a Play install (review
            // N2 / round-3 spoofed-source finding). FLAG_SYSTEM cannot be faked
            // by a sideload, so isSystem is the only source-free fallback.
            // Hash the installed APK only for non-system apps: a stalkerware
            // sample never ships on the system partition, and hashing every
            // framework APK would waste the scan's time budget (item 4).
            val fileSha256 = if (!isSystem) hashApkFile(appInfo?.sourceDir) else null
            val cls = indicators.classify(pkg, certSha1, isSystemApp = isSystem, fileSha256 = fileSha256)
            val isKeyboard = pkg in keyboardPkgs

            val builder = Facts.builder()
                .text(FactKeys.PACKAGE, pkg)
                .text(FactKeys.INSTALL_SOURCE, source)
                .number(FactKeys.INSTALL_TIME, info.firstInstallTime)
                .bool(FactKeys.IS_SYSTEM_APP, isSystem)
                .bool(FactKeys.HAS_LAUNCHER_ICON, hasLauncherIcon(pkg))
                .bool(FactKeys.STARTS_AT_BOOT, "android.permission.RECEIVE_BOOT_COMPLETED" in requested)
                .bool(FactKeys.ACCESSIBILITY_ENABLED, hasAccessibility)
                .bool(FactKeys.DEVICE_ADMIN, hasAdmin)
                .bool(FactKeys.NOTIFICATION_ACCESS, hasNotif)
                .bool(FactKeys.DEFAULT_SMS, isDefaultSms)
                .bool(FactKeys.DEFAULT_DIALER, pkg == defaultDialer)
                .number(FactKeys.SURVEILLANCE_POWER_COUNT, powerCount.toLong())
                .textList(FactKeys.GRANTED_SURVEILLANCE_PERMISSIONS, grantedGroups)
                .number(FactKeys.GRANTED_SURVEILLANCE_PERMISSION_COUNT, grantedGroups.size.toLong())
                .bool(FactKeys.THIRD_PARTY_KEYBOARD, isKeyboard)
                // A keyboard is "known good" when it is a recognised vendor or a
                // system component — those are not flagged (security review H3).
                .bool(FactKeys.IS_KNOWN_GOOD_KEYBOARD, cls.isKnownGoodKeyboard || (isKeyboard && isSystem))
                .bool(FactKeys.INSTALL_SOURCE_MISMATCH, installSourceMismatch(pkg, isSystem))
                .bool(FactKeys.POSES_AS_SYSTEM, posesAsSystem(pkg, isSystem, source))
                .bool(
                    FactKeys.UPLOADS_SCREEN_OFF,
                    com.phonespyguard.watch.ScreenOffTraffic.isSignificant(screenOffBytes[pkg] ?: 0L),
                )
                .bool(FactKeys.KNOWN_STALKERWARE_MATCH, cls.knownStalkerware)
                .bool(FactKeys.KNOWN_STALKERWARE_FILE_MATCH, cls.knownStalkerwareFile)
                .bool(FactKeys.WATCHWARE_MATCH, cls.watchwareMatch)
                .bool(FactKeys.MERCENARY_INDICATOR_MATCH, cls.mercenaryMatch)
                .bool(FactKeys.IS_SCREEN_READER, cls.isScreenReader)
                .bool(FactKeys.IS_PARENTAL_CONTROL, cls.isParentalControl)

            if (cert != null) {
                builder.text(FactKeys.CERT_SHA256, cert)
                val prior = priorCerts[pkg]
                builder.bool(FactKeys.CERT_CHANGED_ON_UPDATE, prior != null && !prior.equals(cert, ignoreCase = true))
            }
            snapshot[pkg] = builder.build()
        }
        return snapshot
    }

    /**
     * The surveillance permission *groups* this app has actually been granted,
     * read from the per-permission grant flags rather than what the manifest
     * merely requests (market-scan item 3). A permission that is requested but
     * the owner has denied, or that a modern OS has auto-revoked, does not count
     * — only a live grant does. The groups are the ones a monitoring product
     * leans on; a single group is returned at most once however many of its
     * permissions are held, so the count reflects breadth of access.
     */
    private fun grantedSurveillanceGroups(info: android.content.pm.PackageInfo): List<String> {
        val names = info.requestedPermissions ?: return emptyList()
        val flags = info.requestedPermissionsFlags
        val groups = linkedSetOf<String>()
        for (i in names.indices) {
            val granted = flags != null && i < flags.size &&
                (flags[i] and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            if (!granted) continue
            SURVEILLANCE_PERMISSION_GROUPS[names[i]]?.let { groups += it }
        }
        return groups.toList()
    }

    /**
     * True when a sideloaded (or unknown-source) app wears a reserved system or
     * vendor package name but is not a genuine system-partition app (item 5).
     * A real framework component is always a system app, and a legitimate store
     * app in the Google namespace arrives from the store; so a non-system,
     * non-store app in these namespaces is impersonating a system component.
     */
    private fun posesAsSystem(pkg: String, isSystem: Boolean, source: String): Boolean {
        if (isSystem) return false
        if (source == "play" || source == "system") return false
        val p = pkg.lowercase()
        return SYSTEM_NAMESPACES.any { p == it.trimEnd('.') || p.startsWith(it) }
    }

    /** Where the app was installed from: system / play / sideload / unknown. */
    private fun installSource(pkg: String, isSystem: Boolean): String {
        if (isSystem) return "system"
        val installer = installingPackage(pkg)
        return when {
            installer == null -> "sideload"
            installer == SHELL -> "sideload"
            installer in KNOWN_STORES -> "play"
            else -> "unknown"
        }
    }

    /**
     * True when the recorded installer looks faked: an app claims a store
     * installer, but the initiating package or package source says it was a
     * local/sideloaded file (security review H4). `adb install -i com.android.
     * vending` is the classic case.
     */
    private fun installSourceMismatch(pkg: String, isSystem: Boolean): Boolean {
        if (isSystem || Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return false
        return runCatching {
            val src = pm.getInstallSourceInfo(pkg)
            val installing = src.installingPackageName
            val initiating = src.initiatingPackageName
            val claimsStore = installing in KNOWN_STORES
            if (!claimsStore) return false
            // Initiator says shell -> faked.
            if (initiating == SHELL) return true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                // packageSource: a local or downloaded file under a store installer is a mismatch.
                when (src.packageSource) {
                    PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE,
                    PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE,
                    -> return true
                }
            }
            false
        }.getOrDefault(false)
    }

    private fun installingPackage(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg)
        }
    }.getOrNull()

    private fun hasLauncherIcon(pkg: String): Boolean {
        val intent = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(pkg)
        return pm.queryIntentActivities(intent, 0).isNotEmpty()
    }

    private fun signingCertBytes(pkg: String): ByteArray? = runCatching {
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        val signingInfo = pm.getPackageInfo(pkg, flags).signingInfo ?: return null
        val signers = if (signingInfo.hasMultipleSigners()) {
            signingInfo.apkContentsSigners
        } else {
            signingInfo.signingCertificateHistory
        }
        signers?.firstOrNull()?.toByteArray()
    }.getOrNull()

    private fun hash(bytes: ByteArray, algorithm: String): String =
        MessageDigest.getInstance(algorithm).digest(bytes)
            .joinToString("") { "%02x".format(it) }

    /**
     * SHA-256 of an installed APK file, streamed so a large base.apk never has
     * to be held in memory (item 4). Returns null when the path is missing or the
     * file cannot be read — a hash we cannot compute simply yields no file match,
     * which fails safe.
     */
    private fun hashApkFile(sourceDir: String?): String? {
        if (sourceDir.isNullOrEmpty()) return null
        return runCatching {
            val digest = MessageDigest.getInstance("SHA-256")
            java.io.File(sourceDir).inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }

    private fun enabledComponentPackages(setting: String): Set<String> {
        val value = Settings.Secure.getString(context.contentResolver, setting) ?: return emptySet()
        return value.split(':')
            .mapNotNull { it.substringBefore('/').ifBlank { null } }
            .toSet()
    }

    private fun activeDeviceAdminPackages(): Set<String> {
        val dpm = context.getSystemService(DevicePolicyManager::class.java) ?: return emptySet()
        return dpm.activeAdmins?.map { it.packageName }?.toSet().orEmpty()
    }

    private fun enabledInputMethodPackages(): Set<String> {
        val imm = context.getSystemService(InputMethodManager::class.java) ?: return emptySet()
        return imm.enabledInputMethodList?.map { it.packageName }?.toSet().orEmpty()
    }

    private companion object {
        const val SHELL = "com.android.shell"

        // Reserved framework / first-party-vendor package namespaces. A genuine
        // app in these is a system app or a store install; a sideloaded one is a
        // disguise (item 5). Kept deliberately tight to avoid flagging an
        // unrelated third-party app that merely starts with one of these.
        val SYSTEM_NAMESPACES = listOf(
            "android.",
            "com.android.",
            "com.google.android.",
            "com.sec.android.",
            "com.samsung.android.",
        )

        // Dangerous runtime permissions mapped to the surveillance group they
        // give access to (market-scan item 3). Only permissions that let an app
        // capture a person's private life are listed; a renamed permission in a
        // future OS simply won't match, which fails safe (it under-counts, never
        // over-accuses).
        val SURVEILLANCE_PERMISSION_GROUPS: Map<String, String> = mapOf(
            "android.permission.RECORD_AUDIO" to "microphone",
            "android.permission.CAMERA" to "camera",
            "android.permission.READ_SMS" to "sms",
            "android.permission.RECEIVE_SMS" to "sms",
            "android.permission.RECEIVE_MMS" to "sms",
            "android.permission.SEND_SMS" to "sms",
            "android.permission.READ_CALL_LOG" to "call_log",
            "android.permission.WRITE_CALL_LOG" to "call_log",
            "android.permission.PROCESS_OUTGOING_CALLS" to "call_log",
            "android.permission.ACCESS_FINE_LOCATION" to "location",
            "android.permission.ACCESS_COARSE_LOCATION" to "location",
            "android.permission.ACCESS_BACKGROUND_LOCATION" to "location",
            "android.permission.READ_CONTACTS" to "contacts",
        )

        // Real app-store installers only. com.google.android.feedback is dropped:
        // it has been used to launder a sideloaded install as a Play one (H4).
        val KNOWN_STORES = setOf(
            "com.android.vending", // Google Play
            "com.sec.android.app.samsungapps", // Samsung Galaxy Store
            "com.amazon.venezia", // Amazon Appstore
            "com.huawei.appmarket", // Huawei AppGallery
        )
    }
}
