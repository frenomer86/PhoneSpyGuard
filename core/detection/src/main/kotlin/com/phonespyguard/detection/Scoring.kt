package com.phonespyguard.detection

/**
 * The confidence levels an evidence card can carry (FR-ATT-05, page 11 of the
 * spec). Ordered from most to least concerning.
 */
public enum class Confidence {
    /** Matches a known spyware product, or a proof test fired. */
    CONFIRMED,

    /** Several strong signals and no innocent explanation. */
    VERY_LIKELY,

    /** Risky powers but no harmful activity seen. */
    POSSIBLE,

    /** Powers fully explained by a legitimate use. */
    UNLIKELY,
}

/** One rule that matched a subject, kept for the evidence card. */
public data class MatchedSignal(
    val ruleId: String,
    val title: String,
    val severity: Severity,
    val contribution: Contribution,
    /** For an INNOCENT signal: the concerning rule ids it explains (see [Rule.explains]). */
    val explains: List<String> = emptyList(),
)

/**
 * The verdict for one subject. Carries every contributing signal and any
 * innocent explanation that was checked, so the card can show its reasoning
 * rather than a bare score (FR-ATT-01, FR-ATT-05, FR-ALR-01).
 */
public data class Verdict(
    val subject: String,
    val confidence: Confidence,
    val signals: List<MatchedSignal>,
    val innocentExplanations: List<MatchedSignal>,
) {
    public val concerning: List<MatchedSignal>
        get() = signals.filter { it.contribution != Contribution.INNOCENT }
}

/**
 * Turns the set of rules that matched a subject into one of the four
 * confidence levels. This is the shared scoring specification; the Rust
 * desktop core (Phase 2) implements the same rules against the same
 * conformance fixtures so the two engines never disagree.
 *
 * An innocent explanation only cancels the signals it actually accounts for
 * (security review H5). Each INNOCENT rule names, in [Rule.explains], the
 * concerning rule ids it explains; a STRONG or RISK signal counts as "explained"
 * only when a matched innocent rule names its id. A CONFIRM signal is never
 * explained — a known stalkerware brand is not excused by looking legitimate.
 *
 * The classification uses only the *unexplained* signals, in order:
 *  1. Any CONFIRM signal            -> CONFIRMED
 *  2. Any unexplained STRONG signal -> VERY_LIKELY
 *  3. Any unexplained RISK signal   -> POSSIBLE
 *  4. Otherwise                     -> UNLIKELY
 *
 * This is the shared scoring specification; the Rust desktop core implements the
 * identical rule against the same conformance fixtures so the engines never
 * disagree.
 */
public class Scoring {
    public fun classify(subject: String, matched: List<MatchedSignal>): Verdict {
        val innocent = matched.filter { it.contribution == Contribution.INNOCENT }
        val concerning = matched.filter { it.contribution != Contribution.INNOCENT }

        // The set of concerning rule ids a matched innocent rule accounts for.
        val explainedIds = innocent.flatMap { it.explains }.toSet()

        // A CONFIRM is never explained away; a STRONG/RISK is explained only when
        // an innocent rule names it.
        val unexplained = concerning.filter {
            it.contribution == Contribution.CONFIRM || it.ruleId !in explainedIds
        }

        val confidence = when {
            unexplained.any { it.contribution == Contribution.CONFIRM } -> Confidence.CONFIRMED
            unexplained.any { it.contribution == Contribution.STRONG } -> Confidence.VERY_LIKELY
            unexplained.any { it.contribution == Contribution.RISK } -> Confidence.POSSIBLE
            else -> Confidence.UNLIKELY
        }

        return Verdict(
            subject = subject,
            confidence = confidence,
            signals = matched,
            innocentExplanations = innocent,
        )
    }
}
