package com.phonespyguard.app.detect

import com.phonespyguard.detection.ActiveBundle
import com.phonespyguard.detection.BundleSignature
import com.phonespyguard.detection.BundleStore
import com.phonespyguard.detection.InstallResult
import com.phonespyguard.detection.RuleBundle
import com.phonespyguard.detection.RuleBundleParser
import com.phonespyguard.detection.RuleUpdateFetcher
import com.phonespyguard.detection.RuleUpdateService
import com.phonespyguard.detection.TrustConfig
import com.phonespyguard.detection.UpdateTransport
import java.time.Instant

/**
 * Loads the detection rule bundle the app runs with, and applies signed updates
 * the same way the desktop and iPhone apps do (FR-RUL-01, round-3 review:
 * "Android can't receive rule updates").
 *
 * The signed launch bundle ships in the detection module's resources, trusted
 * via the APK signature. A *downloaded* update is applied only after
 * [RuleUpdateService] confirms a 2-of-3 signature over the exact payload bytes
 * (from the same `trusted-keys.json` the other platforms ship), a version no
 * older than the one in force, and a non-expired payload. A verified update is
 * then preferred over the shipped bundle; a tampered, under-signed, rolled-back
 * or expired update is refused and the shipped rules keep working.
 *
 * Whatever bundle is in force, [isExpired] is surfaced so the app never presents
 * a scan from stale rules as current (security review M3).
 */
public object RuleBundleProvider {

    private val parser = RuleBundleParser()

    @Volatile
    private var updateStore: BundleStore? = null

    @Volatile
    private var cached: ActiveBundle? = null

    /**
     * Attach the encrypted store that holds a downloaded update. Called once at
     * app start; until then only the shipped bundle is used.
     */
    public fun attachUpdateStore(store: BundleStore) {
        updateStore = store
        cached = null
    }

    public fun bundle(): RuleBundle = active().bundle

    /** "update" when a verified downloaded bundle is in force, else "shipped". */
    public fun source(): String = active().source

    /** A stored update that no longer verifies, surfaced so the app can warn. */
    public fun updateWarning(): String? = active().warning

    public fun isExpired(now: Instant = Instant.now()): Boolean = bundle().isExpired(now)

    /**
     * Offer a freshly downloaded update (payload bytes and its detached
     * signatures). Verified and persisted on success; nothing stored on refusal.
     */
    public fun installUpdate(payload: ByteArray, signatures: List<BundleSignature>): InstallResult {
        val store = updateStore ?: return InstallResult.Refused("No update store configured")
        val shippedPayload = loadShippedPayload()
        val shippedVersion = parser.parse(shippedPayload.decodeToString()).version
        val result = RuleUpdateService(trustConfig(), store).tryInstall(payload, signatures, shippedVersion)
        if (result is InstallResult.Installed) cached = null // reload on next access
        return result
    }

    /**
     * Download a signed update over [transport] and apply it if it verifies
     * (market-scan item 2). Returns the outcome; on success the next [bundle]
     * call reloads the new rules. Nothing identifying is sent — see
     * [UpdateTransport].
     */
    public fun fetchUpdate(transport: UpdateTransport, payloadUrl: String, signaturesUrl: String): InstallResult {
        val store = updateStore ?: return InstallResult.Refused("No update store configured")
        val shippedVersion = parser.parse(loadShippedPayload().decodeToString()).version
        val service = RuleUpdateService(trustConfig(), store)
        val result = RuleUpdateFetcher(service, transport, payloadUrl, signaturesUrl).fetchAndInstall(shippedVersion)
        if (result is InstallResult.Installed) cached = null
        return result
    }

    private fun active(): ActiveBundle {
        cached?.let { return it }
        val shippedPayload = loadShippedPayload()
        val shipped = parser.parse(shippedPayload.decodeToString())
        val store = updateStore
        val result = if (store != null) {
            RuleUpdateService(trustConfig(), store).active(shipped, shippedPayload)
        } else {
            ActiveBundle(shipped, "shipped")
        }
        cached = result
        return result
    }

    private fun loadShippedPayload(): ByteArray =
        javaClass.getResourceAsStream("/rules/launch-bundle.json")?.readBytes()
            ?: error("bundled rule set missing")

    private fun trustConfig(): TrustConfig {
        val text = javaClass.getResourceAsStream("/rules/trusted-keys.json")
            ?.readBytes()?.decodeToString()
            ?: error("trusted-keys.json missing")
        return TrustConfig.parse(text)
    }
}
