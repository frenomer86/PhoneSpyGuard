package com.phonespyguard.app.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * A lock in front of the app's sensitive screens (NFR-SEC-06/07, review C4).
 *
 * Results and the evidence export sit behind a biometric or device-credential
 * prompt, so someone who picks up an unlocked phone cannot read what the app
 * found or who was flagged. If the device has no lock set up at all, the gate
 * opens (there is nothing to check against), which the UI tells the owner.
 */
public object AppLock {

    public fun isAvailable(activity: FragmentActivity): Boolean {
        val status = BiometricManager.from(activity).canAuthenticate(ALLOWED)
        return status == BiometricManager.BIOMETRIC_SUCCESS
    }

    /** Prompt to unlock; [onResult] gets true only on a successful auth. */
    public fun prompt(activity: FragmentActivity, onResult: (Boolean) -> Unit) {
        if (!isAvailable(activity)) {
            // No device lock configured — nothing to authenticate against.
            onResult(true)
            return
        }
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onResult(true)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onResult(false)
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock to continue")
            .setSubtitle("Confirm it's you before viewing your results")
            .setAllowedAuthenticators(ALLOWED)
            .build()
        prompt.authenticate(info)
    }

    private const val ALLOWED =
        BiometricManager.Authenticators.BIOMETRIC_WEAK or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
}
