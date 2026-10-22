package com.phonespyguard.app.security

import android.content.Context
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.util.Base64

/**
 * An optional app-only PIN, separate from the device lock (security review N4).
 *
 * In partner abuse the abuser usually knows the phone's PIN — that is often how
 * the spyware was installed — so the device credential alone is not enough to
 * keep this app's results private. The owner can set a PIN that only unlocks
 * this app. It is stored as a salted PBKDF2 hash inside the Keystore-encrypted
 * blob, never in clear text, and is checked entirely on the device.
 */
public class AppPin(context: Context) {

    private val store = EncryptedBlobStore(context, "app-pin.json")

    public fun isSet(): Boolean = store.exists() && store.read() != null

    public fun setPin(pin: String) {
        require(pin.length >= MIN_LENGTH) { "PIN must be at least $MIN_LENGTH digits" }
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val hash = pbkdf2(pin, salt)
        val json = JSONObject()
            .put("salt", b64(salt))
            .put("hash", b64(hash))
            .put("iterations", ITERATIONS)
        store.write(json.toString())
    }

    public fun clear() {
        // Overwrite with an empty marker, then it reads back as "not set".
        runCatching { store.quarantine() }
    }

    /** True when [pin] matches the stored PIN. Constant-time compare. */
    public fun verify(pin: String): Boolean {
        val text = store.read() ?: return false
        return runCatching {
            val json = JSONObject(text)
            val salt = unb64(json.getString("salt"))
            val expected = unb64(json.getString("hash"))
            val actual = pbkdf2(pin, salt, json.optInt("iterations", ITERATIONS))
            constantTimeEquals(expected, actual)
        }.getOrDefault(false)
    }

    private fun pbkdf2(pin: String, salt: ByteArray, iterations: Int = ITERATIONS): ByteArray {
        val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun unb64(s: String) = Base64.getDecoder().decode(s)

    private companion object {
        const val MIN_LENGTH = 4
        const val ITERATIONS = 120_000
    }
}
