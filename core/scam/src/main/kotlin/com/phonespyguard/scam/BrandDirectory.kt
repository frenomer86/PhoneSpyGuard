package com.phonespyguard.scam

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** One brand a scam message is likely to impersonate, and its real domains. */
@Serializable
public data class Brand(
    val name: String,
    /** Lower-case tokens that name the brand, e.g. `["paypal"]`, `["mtn", "momo"]`. */
    val aliases: List<String>,
    /** The brand's genuine registrable domains, e.g. `["paypal.com"]`. */
    val domains: List<String>,
)

@Serializable
private data class BrandFile(val brands: List<Brand>)

/**
 * The brands a phishing message most often pretends to be, mapped to the domains
 * those brands actually use. Two scam checks lean on it: a brand word appearing
 * as a *subdomain* of someone else's domain (`mtn.secure-login.ru`), and a
 * registrable domain that is a near look-alike of a real one (`paypa1.com`).
 *
 * It ships as a bundled data file covering the global brands plus the banks and
 * mobile-money services a victim in the app's launch regions is likely to see.
 */
public class BrandDirectory private constructor(
    private val brands: List<Brand>,
) {
    public val size: Int get() = brands.size

    public fun all(): List<Brand> = brands

    /** Every genuine domain across all brands. */
    public fun allDomains(): List<String> = brands.flatMap { it.domains }

    /** The brand that owns this registrable domain, if any. */
    public fun brandForDomain(registrableDomain: String): Brand? {
        val d = registrableDomain.lowercase()
        return brands.firstOrNull { b -> b.domains.any { it.equals(d, ignoreCase = true) } }
    }

    /** The brand whose alias is exactly this token, if any. */
    public fun brandForAlias(token: String): Brand? {
        val t = token.lowercase()
        return brands.firstOrNull { b -> b.aliases.any { it == t } }
    }

    public companion object {
        public fun fromJson(text: String): BrandDirectory {
            val parsed = Json { ignoreUnknownKeys = true }.decodeFromString<BrandFile>(text)
            return BrandDirectory(parsed.brands)
        }

        public fun bundled(): BrandDirectory {
            val text = BrandDirectory::class.java
                .getResourceAsStream("/scam/brand-directory.json")
                ?.readBytes()?.toString(Charsets.UTF_8)
                ?: error("bundled brand directory missing")
            return fromJson(text)
        }
    }
}
