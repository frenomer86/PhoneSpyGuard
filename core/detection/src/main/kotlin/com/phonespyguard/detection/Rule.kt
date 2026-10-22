package com.phonespyguard.detection

/**
 * Severity of a finding a rule produces. Mirrors the spec's rule format.
 */
public enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }

/**
 * How a matched rule contributes to the confidence verdict (FR-ATT-05).
 *
 * The four confidence levels — Confirmed, Very likely, Possible, Unlikely —
 * are derived from the mix of contributions a subject collects, never from a
 * single rule in isolation. See [Scoring].
 */
public enum class Contribution {
    /** A known spyware product matched, or a proof test fired -> Confirmed. */
    CONFIRM,

    /** A strong behavioural signal, e.g. uploads while the screen was off. */
    STRONG,

    /** A risky power with no harmful activity seen, e.g. an unused keyboard. */
    RISK,

    /** Evidence of a legitimate use that can explain risky powers away. */
    INNOCENT,
}

/**
 * A single detection rule.
 *
 * A rule is *data the engine evaluates, never code it runs* (FR-RUL-01,
 * NFR-SEC-16). It can only ask whether facts the collectors already read match
 * a bounded predicate tree. Everything a rule can "do" is describe a finding.
 */
public data class Rule(
    val id: String,
    val version: Int,
    val severity: Severity,
    val title: String,
    val contribution: Contribution,
    /** The predicate tree evaluated against a subject's facts. */
    val condition: Condition,
    /** Which evidence sections an alert for this rule should show. */
    val evidence: List<String> = emptyList(),
    /** A plain-language explanation shown to the owner (FR-ALR-01). */
    val explain: String = "",
    /** Suggested next steps, e.g. remove_device_admin, uninstall (FR-ALR-02). */
    val steps: List<String> = emptyList(),
    /**
     * For an INNOCENT rule only: the ids of the concerning rules this innocent
     * explanation accounts for. A STRONG or RISK signal is cancelled only when a
     * matched innocent rule names its id here — so a screen-reader explanation
     * can excuse the accessibility power it accounts for without also excusing an
     * unrelated "uploads while the screen is off" signal (security review H5).
     * Empty means the rule explains nothing.
     */
    val explains: List<String> = emptyList(),
    /** Whether a match is written to the evidence timeline (FR-EVD-01). */
    val log: Boolean = true,
)

/**
 * The predicate tree. A sealed hierarchy so evaluation is total and bounded;
 * there is no path by which a rule can express anything but fact matching.
 */
public sealed interface Condition {
    /** True only if every child is true. */
    public data class All(val of: List<Condition>) : Condition

    /** True if any child is true. */
    public data class Any(val of: List<Condition>) : Condition

    /** True if the wrapped condition is false. */
    public data class Not(val of: Condition) : Condition

    /** A leaf test against one fact. */
    public data class Fact(val key: String, val op: Operator) : Condition
}

/**
 * The closed set of operators a leaf predicate may use. No operator can read a
 * second fact, call out, or loop — matching is a single comparison.
 */
public sealed interface Operator {
    public data class Eq(val value: FactValue) : Operator
    public data class In(val values: List<String>) : Operator
    public data class Gt(val value: Long) : Operator
    public data class Gte(val value: Long) : Operator
    public data class Lt(val value: Long) : Operator
    public data class Lte(val value: Long) : Operator
    public data class Contains(val value: String) : Operator
    public data object Exists : Operator
}
