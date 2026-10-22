package com.phonespyguard.app.security

import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import android.content.Context
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Reads and writes one encrypted text blob on disk (NFR-SEC-12, security review
 * C3/M2/N3). The key is held in the Android Keystore via [MasterKey], so the
 * file is unreadable to another app or to someone who copies it off the device.
 *
 * Two properties matter for evidence that a victim relies on (review N3):
 *  - a write is atomic: the new content is written to a temp file and then
 *    renamed over the target, so a crash mid-write never leaves a half file or
 *    an empty one;
 *  - a read tells apart "nothing stored yet" from "stored but unreadable", so
 *    the caller can refuse to overwrite a chain it merely failed to decrypt.
 */
public class EncryptedBlobStore(context: Context, fileName: String) {

    private val appContext = context.applicationContext
    private val file = File(appContext.filesDir, fileName)

    private val masterKey: MasterKey = MasterKey.Builder(appContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private fun encryptedFile(target: File): EncryptedFile = EncryptedFile.Builder(
        appContext,
        target,
        masterKey,
        EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
    ).build()

    public fun exists(): Boolean = file.exists()

    /** The outcome of a read: nothing stored, the stored text, or an unreadable file. */
    public sealed interface ReadResult {
        public data object Absent : ReadResult
        public data class Ok(val text: String) : ReadResult
        public data class Unreadable(val cause: Throwable) : ReadResult
    }

    public fun readResult(): ReadResult {
        if (!file.exists()) return ReadResult.Absent
        return runCatching {
            encryptedFile(file).openFileInput().use { it.readBytes().toString(Charsets.UTF_8) }
        }.fold({ ReadResult.Ok(it) }, { ReadResult.Unreadable(it) })
    }

    /** Convenience read: the text, or null when absent or unreadable. */
    public fun read(): String? = (readResult() as? ReadResult.Ok)?.text

    /**
     * Write atomically. EncryptedFile refuses to overwrite, so write to a fresh
     * temp file and then rename it over the target in one step (review N3).
     */
    public fun write(text: String) {
        val temp = File(appContext.filesDir, file.name + ".tmp")
        if (temp.exists()) temp.delete()
        encryptedFile(temp).openFileOutput().use { it.write(text.toByteArray(Charsets.UTF_8)) }
        Files.move(
            temp.toPath(),
            file.toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
        )
    }

    /**
     * Move an unreadable file aside instead of destroying it, returning the new
     * name. The caller starts a fresh store but the old bytes are preserved for
     * forensic recovery (review N3).
     */
    public fun quarantine(): String? {
        if (!file.exists()) return null
        val aside = File(appContext.filesDir, "${file.name}.corrupt-${System.currentTimeMillis()}")
        return if (file.renameTo(aside)) aside.name else null
    }
}
