package com.phonespyguard.safety

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
private data class PlaybookFile(
    val cards: List<SafetyCard>,
    val support: List<SupportResource>,
)

/**
 * The safety guidance the app shows alongside any result (FR-SAF, FR-ALR).
 *
 * The guiding rule, baked into the ordering: a victim may share a home with the
 * person monitoring them, so safety and evidence come before clean-up. When a
 * scan confirms spyware, the app does not open with a "Remove" button — it opens
 * with how to stay safe and how to keep the proof.
 */
public class SafetyPlaybook private constructor(
    private val cards: List<SafetyCard>,
    private val support: List<SupportResource>,
) {
    /** Cards for a situation, most important first, with the GENERAL cards appended. */
    public fun cardsFor(situation: SafetySituation): List<SafetyCard> {
        val specific = cards.filter { it.situation == situation }
        val general = if (situation == SafetySituation.GENERAL) emptyList()
        else cards.filter { it.situation == SafetySituation.GENERAL }
        return (specific + general).sortedBy { it.priority }
    }

    public fun allCards(): List<SafetyCard> = cards.sortedBy { it.priority }

    /** Support resources for a country, always including international ones. */
    public fun supportFor(country: String): List<SupportResource> {
        val iso = country.uppercase()
        return support.filter { it.country.uppercase() == iso || it.country.uppercase() == "INTL" }
    }

    public val cardCount: Int get() = cards.size
    public val supportCount: Int get() = support.size

    public companion object {
        public fun fromJson(text: String): SafetyPlaybook {
            val parsed = Json { ignoreUnknownKeys = true }.decodeFromString<PlaybookFile>(text)
            return SafetyPlaybook(parsed.cards, parsed.support)
        }

        public fun bundled(): SafetyPlaybook {
            val text = SafetyPlaybook::class.java
                .getResourceAsStream("/safety/safety-playbook.json")
                ?.readBytes()?.toString(Charsets.UTF_8)
                ?: error("bundled safety playbook missing")
            return fromJson(text)
        }
    }
}

/**
 * Maps a detection outcome to the safety situation whose guidance should lead.
 * Kept as a small self-contained enum so this module does not depend on the
 * detection engine.
 */
public enum class DetectionOutcome { CONFIRMED, VERY_LIKELY, POSSIBLE, UNLIKELY, NONE }

/** Chooses which safety guidance to surface for a given result. */
public class SafetyAdvisor(private val playbook: SafetyPlaybook = SafetyPlaybook.bundled()) {
    /**
     * The ordered safety cards to show for a device-scan outcome. A confirmed or
     * very-likely result leads with "before you remove anything"; a possible
     * result leads with the suspect-monitored guidance.
     */
    public fun forDeviceOutcome(outcome: DetectionOutcome): List<SafetyCard> = when (outcome) {
        DetectionOutcome.CONFIRMED, DetectionOutcome.VERY_LIKELY -> {
            val before = playbook.cardsFor(SafetySituation.BEFORE_REMOVING)
            val confirmed = playbook.cardsFor(SafetySituation.CONFIRMED_SPYWARE)
                .filter { it.situation != SafetySituation.GENERAL }
            (before + confirmed).distinctBy { it.id }.sortedBy { it.priority }
        }
        DetectionOutcome.POSSIBLE -> playbook.cardsFor(SafetySituation.SUSPECT_MONITORED)
        DetectionOutcome.UNLIKELY, DetectionOutcome.NONE -> playbook.cardsFor(SafetySituation.GENERAL)
    }

    public fun forPhoneFraud(): List<SafetyCard> = playbook.cardsFor(SafetySituation.PHONE_FRAUD)
}
