package com.phonespyguard.detection

/** Thrown when evaluation exceeds the configured time budget. */
public class EvaluationBudgetExceeded(message: String) : RuntimeException(message)

/**
 * Limits that bound rule evaluation (NFR-SEC-16).
 *
 * Node count and nesting depth are enforced when a bundle is parsed (see
 * [RuleBundleParser]); the time budget is enforced here, per subject, so a
 * pathological bundle that slipped past parsing still cannot hang a scan.
 */
public data class EvaluationLimits(
    val maxConditionNodes: Int = 256,
    val maxDepth: Int = 16,
    val maxEvaluationMillis: Long = 250,
) {
    public companion object {
        public val DEFAULT: EvaluationLimits = EvaluationLimits()
    }
}

/**
 * Evaluates a [Condition] against [Facts]. Pure, total, and bounded: it reads
 * facts, compares, and combines with and/or/not — nothing else. There is no
 * code path that executes data from a bundle.
 */
public class BoundedInterpreter(
    private val limits: EvaluationLimits = EvaluationLimits.DEFAULT,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    public fun matches(condition: Condition, facts: Facts): Boolean {
        val deadline = clock() + limits.maxEvaluationMillis
        return eval(condition, facts, depth = 0, deadline = deadline)
    }

    private fun eval(condition: Condition, facts: Facts, depth: Int, deadline: Long): Boolean {
        if (clock() > deadline) {
            throw EvaluationBudgetExceeded(
                "Rule evaluation exceeded ${limits.maxEvaluationMillis} ms budget",
            )
        }
        // Depth is also checked at parse time; this is defence in depth.
        if (depth > limits.maxDepth) {
            throw EvaluationBudgetExceeded("Rule nesting exceeded depth ${limits.maxDepth}")
        }

        return when (condition) {
            is Condition.All -> condition.of.all { eval(it, facts, depth + 1, deadline) }
            is Condition.Any -> condition.of.any { eval(it, facts, depth + 1, deadline) }
            is Condition.Not -> !eval(condition.of, facts, depth + 1, deadline)
            is Condition.Fact -> evalLeaf(condition, facts)
        }
    }

    private fun evalLeaf(leaf: Condition.Fact, facts: Facts): Boolean {
        val value = facts[leaf.key]
        return when (val op = leaf.op) {
            is Operator.Exists -> value != null
            is Operator.Eq -> value != null && valuesEqual(value, op.value)
            is Operator.In -> value is FactValue.Text && value.value in op.values
            is Operator.Contains ->
                value is FactValue.TextList && op.value in value.values
            is Operator.Gt -> asNumber(value)?.let { it > op.value } ?: false
            is Operator.Gte -> asNumber(value)?.let { it >= op.value } ?: false
            is Operator.Lt -> asNumber(value)?.let { it < op.value } ?: false
            is Operator.Lte -> asNumber(value)?.let { it <= op.value } ?: false
        }
    }

    private fun asNumber(value: FactValue?): Long? =
        (value as? FactValue.Number)?.value

    private fun valuesEqual(a: FactValue, b: FactValue): Boolean = when {
        a is FactValue.Text && b is FactValue.Text -> a.value == b.value
        a is FactValue.Bool && b is FactValue.Bool -> a.value == b.value
        a is FactValue.Number && b is FactValue.Number -> a.value == b.value
        else -> false
    }
}
