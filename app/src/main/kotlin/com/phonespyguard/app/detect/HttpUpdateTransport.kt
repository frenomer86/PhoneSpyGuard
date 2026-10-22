package com.phonespyguard.app.detect

import com.phonespyguard.detection.UpdateTransport
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches a rule-update file over HTTPS with a plain GET and nothing else: no
 * cookies, no account, no custom identifying headers, no query string (market-
 * scan item 2, "nothing identifying sent"). The request reveals only that some
 * device asked for the current public rule file. Only https:// URLs are allowed,
 * the response is size-capped so a hostile server can't exhaust memory, and the
 * bytes are meaningless unless they later pass the 2-of-3 signature check.
 */
public class HttpUpdateTransport(
    private val maxBytes: Int = 2 * 1024 * 1024,
    private val timeoutMillis: Int = 15_000,
) : UpdateTransport {

    override fun get(url: String): ByteArray {
        val parsed = URL(url)
        require(parsed.protocol == "https") { "Rule updates must be fetched over https" }
        val conn = (parsed.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMillis
            readTimeout = timeoutMillis
            instanceFollowRedirects = true
            useCaches = false
            // No identifying headers. A neutral, generic UA only.
            setRequestProperty("User-Agent", "PhoneSpyGuard")
            setRequestProperty("Accept", "application/json")
        }
        try {
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw IOException("HTTP $code")
            conn.inputStream.use { input ->
                val buffer = ByteArray(8 * 1024)
                val out = java.io.ByteArrayOutputStream()
                var total = 0
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    total += n
                    if (total > maxBytes) throw IOException("Rule file exceeds $maxBytes bytes")
                    out.write(buffer, 0, n)
                }
                return out.toByteArray()
            }
        } finally {
            conn.disconnect()
        }
    }
}
