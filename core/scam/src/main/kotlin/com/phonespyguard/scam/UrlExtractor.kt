package com.phonespyguard.scam

/**
 * A single link pulled out of a message, broken into the parts the scam checks
 * look at. Everything here is derived on the device from the text itself — no
 * network call is made to resolve or expand anything.
 */
public data class ParsedUrl(
    /** The link as it appeared in the message, after de-obfuscation. */
    val raw: String,
    val scheme: String,
    /** The host, lower-cased. For `www.Paypal.COM` this is `www.paypal.com`. */
    val host: String,
    /** The registrable domain (eTLD+1), e.g. `paypal.com` for `login.paypal.com`. */
    val registrableDomain: String,
    /** The labels in front of the registrable domain, e.g. `["login", "secure"]`. */
    val subdomains: List<String>,
    val path: String,
    /** True when the host is a bare IPv4/IPv6 literal instead of a name. */
    val isIpHost: Boolean,
    /** True when any label is IDNA punycode (`xn--`), a common look-alike trick. */
    val isPunycode: Boolean,
    /** The user-info part before an `@`, e.g. `paypal.com` in `paypal.com@evil.ru`. */
    val userInfo: String?,
)

/**
 * Finds and normalises links inside a message (FR-CHK-05). Scam texts routinely
 * disguise links — `hxxp`, `paypal[.]com`, spaces, zero-width characters, a
 * trusted-looking name before an `@` — so before anything is judged the text is
 * de-obfuscated into plain URLs, then each is parsed into [ParsedUrl].
 *
 * This runs entirely on the device and never contacts the link.
 */
public class UrlExtractor(
    private val publicSuffixes: Set<String> = PublicSuffixes.COMMON,
) {
    public fun extract(message: String): List<ParsedUrl> {
        val cleaned = deobfuscate(message)
        val out = LinkedHashMap<String, ParsedUrl>()
        for (match in CANDIDATE.findAll(cleaned)) {
            val token = match.value.trim().trimEnd(*TRAILING_PUNCT)
            val parsed = parse(token) ?: continue
            // De-duplicate on the raw text so the same link counted once.
            out.putIfAbsent(parsed.raw, parsed)
        }
        return out.values.toList()
    }

    /** Parse a single already-isolated link, or null if it is not a usable URL. */
    public fun parse(token: String): ParsedUrl? {
        var rest = token
        val scheme: String
        val schemeMatch = SCHEME.find(rest)
        if (schemeMatch != null) {
            scheme = schemeMatch.groupValues[1].lowercase()
            rest = rest.substring(schemeMatch.value.length)
        } else {
            scheme = "http"
        }

        // Split authority from path/query/fragment.
        val authorityEnd = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
        val authority = if (authorityEnd >= 0) rest.substring(0, authorityEnd) else rest
        val path = if (authorityEnd >= 0) rest.substring(authorityEnd) else ""

        // Pull off any user-info (`user:pass@host`) — the `@` host-spoof trick.
        var hostPart = authority
        var userInfo: String? = null
        val at = authority.lastIndexOf('@')
        if (at >= 0) {
            userInfo = authority.substring(0, at)
            hostPart = authority.substring(at + 1)
        }

        // Drop a port if present (but keep IPv6 brackets intact).
        hostPart = stripPort(hostPart)
        if (hostPart.isEmpty()) return null

        val host = hostPart.lowercase()
        val isIp = IPV4.matches(host) || host.startsWith("[")
        val isPunycode = host.split('.').any { it.startsWith("xn--") }

        val (registrable, subs) = if (isIp) {
            host to emptyList()
        } else {
            registrable(host)
        }
        // A plain word with no dot and no scheme is not a link.
        if (!isIp && !host.contains('.')) return null

        return ParsedUrl(
            raw = token,
            scheme = scheme,
            host = host,
            registrableDomain = registrable,
            subdomains = subs,
            path = path,
            isIpHost = isIp,
            isPunycode = isPunycode,
            userInfo = userInfo?.takeIf { it.isNotEmpty() },
        )
    }

    private fun stripPort(host: String): String {
        if (host.startsWith("[")) { // IPv6 literal `[::1]:443`
            val close = host.indexOf(']')
            return if (close >= 0) host.substring(0, close + 1) else host
        }
        val colon = host.indexOf(':')
        return if (colon >= 0) host.substring(0, colon) else host
    }

    /** Split a host into (registrable domain, subdomain labels) using the suffix list. */
    private fun registrable(host: String): Pair<String, List<String>> {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size <= 1) return host to emptyList()
        // Find the longest public suffix that matches the tail.
        var suffixLen = 1
        for (len in minOf(labels.size - 1, 3) downTo 1) {
            val candidate = labels.takeLast(len).joinToString(".")
            if (candidate in publicSuffixes) { suffixLen = len; break }
        }
        val registrableLen = suffixLen + 1
        if (labels.size <= registrableLen) return host to emptyList()
        val registrable = labels.takeLast(registrableLen).joinToString(".")
        val subs = labels.dropLast(registrableLen)
        return registrable to subs
    }

    public companion object {
        private val SCHEME = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*)://")
        private val IPV4 = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        // A link candidate: optional scheme, a dotted host, optional path. Also
        // matches bare domains like `paypal-secure.com/login`.
        private val CANDIDATE = Regex(
            """((?:[a-zA-Z][a-zA-Z0-9+.-]*://)?(?:[^\s/@]+@)?(?:\[[0-9a-fA-F:]+\]|[\w-]+(?:\.[\w-]+)+)(?::\d+)?(?:/[^\s]*)?)""",
        )
        private val TRAILING_PUNCT = charArrayOf('.', ',', ')', ']', '}', '"', '\'', '!', '?', ';', ':')

        /** Undo the common ways scammers break a URL so filters miss it. */
        public fun deobfuscate(text: String): String {
            var s = text
            // Strip zero-width and bidi characters used to hide look-alikes.
            s = s.replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]"), "")
            s = s.replace(Regex("(?i)h(?:xx|XX|tt)p(s?)://"), "http$1://")
            s = s.replace(Regex("(?i)^\\s*hxxp"), "http")
            // `[.]`, `(.)`, `{dot}`, ` dot ` → `.`   and `[:]`, `[@]` → the char.
            s = s.replace(Regex("""\s*[\[(\{]\s*\.\s*[\])\}]\s*"""), ".")
            s = s.replace(Regex("""(?i)\s+dot\s+"""), ".")
            s = s.replace(Regex("""[\[(\{]\s*:\s*[\])\}]"""), ":")
            s = s.replace(Regex("""[\[(\{]\s*@\s*[\])\}]"""), "@")
            return s
        }
    }
}
