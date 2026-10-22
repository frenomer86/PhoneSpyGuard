package com.phonespyguard.detection

/**
 * The detection engine: evaluates a validated [RuleBundle] against the facts
 * for a subject and returns a [Verdict].
 *
 * It has no network access and no Android dependencies of its own
 * (NFR-MNT-01). The Android app feeds it facts gathered by collectors and
 * renders the verdict; the desktop Rust core (Phase 2) does the same against
 * the same rules and the same scoring spec.
 *
 * A rule whose evaluation exceeds the time budget is skipped rather than
 * allowed to hang a scan — the skip is reported so the engine never silently
 * presents a scan as complete when a rule could not run (FR-CHK-03).
 */
public class DetectionEngine(
    private val bundle: RuleBundle,
    limits: EvaluationLimits = EvaluationLimits.DEFAULT,
) {
    private val interpreter = BoundedInterpreter(limits)
    private val scoring = Scoring()

    /** The outcome of evaluating one subject, including any rules that could
     *  not be evaluated within budget. */
    public data class Evaluation(
        val verdict: Verdict,
        val skippedRuleIds: List<String>,
    )

    public fun evaluate(subject: String, facts: Facts): Evaluation {
        val matched = mutableListOf<MatchedSignal>()
        val skipped = mutableListOf<String>()

        for (rule in bundle.rules) {
            val isMatch = try {
                interpreter.matches(rule.condition, facts)
            } catch (_: EvaluationBudgetExceeded) {
                skipped.add(rule.id)
                continue
            }
            if (isMatch) {
                matched.add(
                    MatchedSignal(
                        ruleId = rule.id,
                        title = rule.title,
                        severity = rule.severity,
                        contribution = rule.contribution,
                        explains = rule.explains,
                    ),
                )
            }
        }

        return Evaluation(
            verdict = scoring.classify(subject, matched),
            skippedRuleIds = skipped,
        )
    }
}
