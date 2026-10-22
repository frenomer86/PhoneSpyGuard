package com.phonespyguard.app.detect

import android.content.Context
import android.util.Base64
import com.phonespyguard.app.security.EncryptedBlobStore
import com.phonespyguard.detection.BundleSignature
import com.phonespyguard.detection.StoredUpdate
import org.json.JSONArray
import org.json.JSONObject

/**
 * Holds a downloaded, verified rule-bundle update in the app's encrypted store
 * (round-3 review: signed rule updates on Android). The payload bytes and their
 * detached signatures are written as one encrypted blob; [RuleBundleProvider]
 * re-verifies them on every load, so storage is for convenience, never trust.
 */
public class EncryptedBundleStore(context: Context) : com.phonespyguard.detection.BundleStore {

    private val blob = EncryptedBlobStore(context, UPDATE_FILE)

    override fun read(): StoredUpdate? {
        val text = blob.read() ?: return null
        return runCatching {
            val obj = JSONObject(text)
            val payload = Base64.decode(obj.getString("payload"), Base64.NO_WRAP)
            val sigs = obj.getJSONArray("signatures")
            val signatures = (0 until sigs.length()).map { i ->
                val s = sigs.getJSONObject(i)
                BundleSignature(s.getString("keyId"), Base64.decode(s.getString("signature"), Base64.NO_WRAP))
            }
            StoredUpdate(payload, signatures)
        }.getOrNull()
    }

    override fun write(update: StoredUpdate) {
        val sigs = JSONArray()
        update.signatures.forEach { sig ->
            sigs.put(
                JSONObject()
                    .put("keyId", sig.keyId)
                    .put("signature", Base64.encodeToString(sig.signature, Base64.NO_WRAP)),
            )
        }
        val obj = JSONObject()
            .put("payload", Base64.encodeToString(update.payload, Base64.NO_WRAP))
            .put("signatures", sigs)
        blob.write(obj.toString())
    }

    override fun clear() {
        blob.quarantine()
    }

    private companion object {
        const val UPDATE_FILE = "rule-update.json"
    }
}
