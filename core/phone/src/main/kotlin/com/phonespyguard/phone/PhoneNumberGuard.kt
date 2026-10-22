package com.phonespyguard.phone

/** A phone-number alert the guard can raise, each with a plain explanation. */
public sealed interface PhoneAlert {
    public val explanation: String

    /** Unconditional call forwarding switched on (FR-PHN-01). */
    public data class CallForwardingOn(override val explanation: String) : PhoneAlert

    /** The SIM lost service for too long while Wi-Fi still works (FR-PHN-03). */
    public data class SimSwapSuspected(
        val outageMillis: Long,
        override val explanation: String,
    ) : PhoneAlert
}

/**
 * Pure decision logic for the phone-number guard.
 *
 * The Android layer feeds it telephony signals (the call-forwarding indicator
 * from a TelephonyCallback, SIM service state, Wi-Fi state); this decides when
 * an alert is warranted and what to say. Keeping it pure keeps the thresholds
 * testable and identical across platforms.
 */
public class PhoneNumberGuard(
    /** How long the SIM may be out, while Wi-Fi works, before a SIM-swap alarm
     *  (FR-PHN-03: more than 10 minutes). */
    private val simOutageAlarmMillis: Long = 10 * 60 * 1000,
) {
    /**
     * Evaluate the call-forwarding indicator. An alert fires on the transition
     * from off to on, not while it stays on, so the owner is told once.
     */
    public fun onForwardingIndicator(
        wasForwarding: Boolean,
        isForwarding: Boolean,
    ): PhoneAlert? =
        if (!wasForwarding && isForwarding) {
            PhoneAlert.CallForwardingOn(
                "Your calls are now being forwarded to another number. If you did not set " +
                    "this up, a scammer may be redirecting your calls and one-time codes. " +
                    "You can cancel all forwarding with ${ForwardingCodes.cancelAll().code}.",
            )
        } else {
            null
        }

    /**
     * Evaluate SIM service. A SIM-swap alarm needs the SIM to have been out
     * longer than the threshold *while Wi-Fi still works* — a total blackout
     * (no SIM and no Wi-Fi) is more likely just no coverage, so it does not
     * alarm.
     *
     * @param simServiceLostSinceMillis when the SIM lost service, or null if it
     *   currently has service.
     */
    public fun onSimServiceState(
        simServiceLostSinceMillis: Long?,
        wifiConnected: Boolean,
        nowMillis: Long,
    ): PhoneAlert? {
        if (simServiceLostSinceMillis == null || !wifiConnected) return null
        val outage = nowMillis - simServiceLostSinceMillis
        if (outage <= simOutageAlarmMillis) return null
        return PhoneAlert.SimSwapSuspected(
            outageMillis = outage,
            explanation = "Your SIM has had no service for ${outage / 60_000} minutes while " +
                "Wi-Fi still works. A sudden loss of SIM service can be the first sign of a " +
                "SIM swap, where someone moves your number to their own SIM. Call your " +
                "operator's fraud line from another phone to check.",
        )
    }
}
