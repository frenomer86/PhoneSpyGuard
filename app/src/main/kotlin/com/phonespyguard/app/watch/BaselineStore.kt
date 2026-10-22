package com.phonespyguard.app.watch

import android.content.Context
import com.phonespyguard.app.security.EncryptedBlobStore
import com.phonespyguard.detection.FactKeys
import com.phonespyguard.detection.FactValue
import com.phonespyguard.detection.FactsCodec
import com.phonespyguard.watch.Snapshot

/**
 * Persists the change watcher's baseline snapshot between runs, encrypted at
 * rest (NFR-SEC-12, security review M2 — the baseline is no longer a plaintext
 * file). The serialisation format is the shared [FactsCodec].
 */
public class BaselineStore(context: Context) {
    private val store = EncryptedBlobStore(context, "baseline.json")

    public fun load(): Snapshot =
        store.read()?.let { runCatching { FactsCodec.decodeSnapshot(it) }.getOrDefault(emptyMap()) }
            ?: emptyMap()

    public fun save(snapshot: Snapshot) {
        store.write(FactsCodec.encodeSnapshot(snapshot))
    }

    public fun exists(): Boolean = store.exists()

    /** The signing-cert hash last seen per package, for cert-change detection. */
    public fun priorCerts(): Map<String, String> =
        load().mapNotNull { (pkg, facts) ->
            (facts[FactKeys.CERT_SHA256] as? FactValue.Text)?.value?.let { pkg to it }
        }.toMap()
}
