package com.phonespyguard.phone

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** One verified place to report fraud or get help. */
@Serializable
public data class FraudContact(
    val name: String,
    val number: String,
    val kind: Kind,
) {
    public enum class Kind { OPERATOR_FRAUD_LINE, BANK_SUPPORT, MOBILE_MONEY }
}

/** The verified contacts for one country (keyed by ISO 3166-1 alpha-2). */
@Serializable
public data class CountryContacts(
    val country: String,
    val contacts: List<FraudContact>,
)

@Serializable
private data class DirectoryFile(val countries: List<CountryContacts>)

/**
 * A verified directory of operator fraud lines and bank / mobile-money support
 * numbers per country (FR-PHN-04).
 *
 * It ships as a signed data file and is checked every quarter. When a SIM-swap
 * or call-forwarding alert fires, the app shows the right numbers to call from
 * another phone — and tells the owner to dial from the app's verified list, not
 * from a number a scammer gave them.
 */
public class FraudDirectory private constructor(
    private val byCountry: Map<String, CountryContacts>,
) {
    /** Contacts for a country, or an empty list if it is not yet covered. */
    public fun forCountry(isoCode: String): List<FraudContact> =
        byCountry[isoCode.uppercase()]?.contacts ?: emptyList()

    public fun hasCountry(isoCode: String): Boolean =
        byCountry.containsKey(isoCode.uppercase())

    public val countryCount: Int get() = byCountry.size

    public companion object {
        public fun fromJson(text: String): FraudDirectory {
            val parsed = Json { ignoreUnknownKeys = true }.decodeFromString<DirectoryFile>(text)
            return FraudDirectory(parsed.countries.associateBy { it.country.uppercase() })
        }

        /** Load the bundled starter directory shipped in resources. */
        public fun bundled(): FraudDirectory {
            val text = FraudDirectory::class.java
                .getResourceAsStream("/phone/fraud-directory.json")
                ?.readBytes()?.toString(Charsets.UTF_8)
                ?: error("bundled fraud directory missing")
            return fromJson(text)
        }
    }
}
