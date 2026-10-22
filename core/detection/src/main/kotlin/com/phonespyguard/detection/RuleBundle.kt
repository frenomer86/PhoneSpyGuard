package com.phonespyguard.detection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.Instant

/** A parsed, validated set of detection rules with its metadata. */
public data class RuleBundle(
    val version: Int,
    val expiresAt: Instant,
    val rules: List<Rule>,
    /** The signed indicator-of-compromise set the collector matches apps against. */
    val indicators: IndicatorSet = IndicatorSet(),
) {
    /**
     * Whether these rules are past their expiry (security review M3). The parser
     * does not reject an expired bundle — a victim offline past the expiry date
     * is better served by stale rules than none — but the caller must check this
     * and warn, never present an expired scan as current.
     */
    public fun isExpired(now: Instant = Instant.now()): Boolean = !expiresAt.isAfter(now)
}

/** Raised when a bundle is malformed or breaches a limit. The message is the
 *  reason the app would surface, never a stack trace. */
public class BundleRejected(message: String) : RuntimeException(message)

/** Limits on bundle shape, enforced at parse time (NFR-SEC-16). */
public data class BundleLimits(
    val maxBytes: Int = 256 * 1024,
    val maxRules: Int = 1024,
    val maxConditionNodes: Int = 256,
    val maxDepth: Int = 16,
    val maxExplains: Int = 64,
    val maxIndicators: Int = 8192,
) {
    public companion object {
        public val DEFAULT: BundleLimits = BundleLimits()
    }
}

/**
 * Parses a rule bundle from JSON into typed, bounded [Rule]s.
 *
 * The parser is where "rules are data, never code" is enforced: it accepts only
 * the known node and operator shapes, rejects anything larger or deeper than
 * the limits, and never evaluates while parsing. A bundle that parses cannot
 * express anything but fact matching.
 */
public class RuleBundleParser(private val limits: BundleLimits = BundleLimits.DEFAULT) {

    private val json = Json { ignoreUnknownKeys = true }

    public fun parse(text: String): RuleBundle {
        if (text.toByteArray(Charsets.UTF_8).size > limits.maxBytes) {
            throw BundleRejected("Bundle exceeds ${limits.maxBytes} bytes")
        }

        val root = runCatching { json.parseToJsonElement(text).jsonObject }
            .getOrElse { throw BundleRejected("Bundle is not a JSON object") }

        val version = root["version"]?.jsonPrimitive?.longOrNull?.toInt()
            ?: throw BundleRejected("Bundle has no integer 'version'")

        val expiresAt = root["expires"]?.jsonPrimitive?.content
            ?.let { runCatching { Instant.parse(it) }.getOrNull() }
            ?: throw BundleRejected("Bundle has no valid ISO-8601 'expires'")

        val ruleArray = root["rules"]?.jsonArray
            ?: throw BundleRejected("Bundle has no 'rules' array")
        if (ruleArray.size > limits.maxRules) {
            throw BundleRejected("Bundle has ${ruleArray.size} rules, limit ${limits.maxRules}")
        }

        val rules = ruleArray.map { element ->
            val obj = element as? JsonObject
                ?: throw BundleRejected("A rule entry is not an object")
            parseRule(obj)
        }
        val indicators = parseIndicators(root["indicators"])
        return RuleBundle(
            version = version,
            expiresAt = expiresAt,
            rules = rules,
            indicators = indicators,
        )
    }

    private fun parseRule(obj: JsonObject): Rule {
        val id = obj.str("id") ?: throw BundleRejected("Rule has no 'id'")
        val whenNode = when (val w = obj["when"]) {
            null, is JsonNull -> throw BundleRejected("Rule $id has no 'when'")
            is JsonObject -> w
            else -> throw BundleRejected("Rule $id has a 'when' that is not an object")
        }

        val counter = NodeCounter(limits.maxConditionNodes)
        val condition = parseCondition(whenNode, id, depth = 0, counter = counter)
        val contribution = parseContribution(obj.str("contribution"), id)

        return Rule(
            id = id,
            version = obj["version"]?.jsonPrimitive?.longOrNull?.toInt() ?: 1,
            severity = parseSeverity(obj.str("severity"), id),
            title = obj.str("title") ?: id,
            contribution = contribution,
            condition = condition,
            evidence = obj.strList("evidence"),
            explain = obj.str("explain") ?: "",
            steps = obj.strList("steps"),
            explains = obj.explainsList(id, contribution),
            log = obj["log"]?.jsonPrimitive?.booleanOrNull ?: true,
        )
    }

    private fun parseIndicators(node: JsonElement?): IndicatorSet {
        if (node == null || node is JsonNull) return IndicatorSet()
        val obj = node as? JsonObject
            ?: throw BundleRejected("'indicators' is not an object")
        val set = IndicatorSet(
            stalkerware = obj.indicatorList("stalkerware"),
            mercenary = obj.indicatorList("mercenary"),
            screenReaders = obj.indicatorList("screen_readers"),
            parentalControl = obj.indicatorList("parental_control"),
            knownGoodKeyboards = obj.indicatorList("known_good_keyboards"),
        )
        if (set.size > limits.maxIndicators) {
            throw BundleRejected("Bundle has ${set.size} indicators, limit ${limits.maxIndicators}")
        }
        return set
    }

    private fun JsonObject.indicatorList(key: String): List<AppIndicator> {
        val arr = this[key] as? JsonArray ?: return emptyList()
        return arr.map { element ->
            val o = element as? JsonObject
                ?: throw BundleRejected("Indicator in '$key' is not an object")
            val pkg = o.str("package")
            val cert = o.str("cert_sha1")
            if (pkg == null && cert == null) {
                throw BundleRejected("Indicator in '$key' has neither 'package' nor 'cert_sha1'")
            }
            AppIndicator(
                packageName = pkg,
                certSha1 = cert,
                name = o.str("name") ?: pkg ?: cert!!,
            )
        }
    }

    private fun parseCondition(
        node: JsonObject,
        ruleId: String,
        depth: Int,
        counter: NodeCounter,
    ): Condition {
        counter.count()
        if (depth > limits.maxDepth) {
            throw BundleRejected("Rule $ruleId nests deeper than ${limits.maxDepth}")
        }

        return when {
            "all" in node -> Condition.All(
                node.childList("all", ruleId).map { parseCondition(it, ruleId, depth + 1, counter) },
            )
            "any" in node -> Condition.Any(
                node.childList("any", ruleId).map { parseCondition(it, ruleId, depth + 1, counter) },
            )
            "not" in node -> Condition.Not(
                parseCondition(node.childObject("not", ruleId), ruleId, depth + 1, counter),
            )
            "fact" in node -> parseLeaf(node, ruleId)
            else -> throw BundleRejected("Rule $ruleId has an unknown condition node")
        }
    }

    private fun parseLeaf(node: JsonObject, ruleId: String): Condition.Fact {
        val key = node.str("fact") ?: throw BundleRejected("Rule $ruleId leaf has no 'fact'")
        val op = when {
            "exists" in node -> Operator.Exists
            "eq" in node -> Operator.Eq(toFactValue(node["eq"]!!, ruleId))
            "in" in node -> Operator.In(node.primitiveList("in", ruleId))
            "contains" in node -> Operator.Contains(
                node.str("contains") ?: throw BundleRejected("Rule $ruleId 'contains' is not a string"),
            )
            "gt" in node -> Operator.Gt(node.longOp("gt", ruleId))
            "gte" in node -> Operator.Gte(node.longOp("gte", ruleId))
            "lt" in node -> Operator.Lt(node.longOp("lt", ruleId))
            "lte" in node -> Operator.Lte(node.longOp("lte", ruleId))
            else -> throw BundleRejected("Rule $ruleId leaf for '$key' has no known operator")
        }
        return Condition.Fact(key, op)
    }

    private fun toFactValue(element: JsonElement, ruleId: String): FactValue {
        val prim = element as? JsonPrimitive
            ?: throw BundleRejected("Rule $ruleId has a non-scalar 'eq' value")
        prim.booleanOrNull?.let { return FactValue.Bool(it) }
        prim.longOrNull?.let { return FactValue.Number(it) }
        if (prim.isString) return FactValue.Text(prim.content)
        throw BundleRejected("Rule $ruleId has an unsupported 'eq' value")
    }

    // --- small helpers over the JSON tree ---

    private fun primitiveString(element: JsonElement, ruleId: String): String =
        (element as? JsonPrimitive)?.content
            ?: throw BundleRejected("Rule $ruleId has a non-scalar list entry")

    private fun JsonObject.str(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun JsonObject.strList(key: String): List<String> =
        (this[key] as? JsonArray)?.map { primitiveString(it, key) } ?: emptyList()

    /**
     * The `explains` list for an INNOCENT rule: the concerning rule ids it
     * accounts for. Parse semantics are shared with the Rust engine (security
     * review H5): absent or JSON null is an empty list; anything that is not an
     * array is rejected; every entry must be a JSON string (no coercion of
     * numbers or booleans); at most [BundleLimits.maxExplains] entries; and a
     * non-empty list on a rule that is not INNOCENT is rejected.
     */
    private fun JsonObject.explainsList(ruleId: String, contribution: Contribution): List<String> {
        val raw = this["explains"] ?: return emptyList()
        if (raw is JsonNull) return emptyList()
        val arr = raw as? JsonArray
            ?: throw BundleRejected("Rule $ruleId 'explains' is not an array")
        if (arr.size > limits.maxExplains) {
            throw BundleRejected("Rule $ruleId 'explains' has ${arr.size} entries, limit ${limits.maxExplains}")
        }
        val ids = arr.map { element ->
            val prim = element as? JsonPrimitive
            if (prim == null || !prim.isString) {
                throw BundleRejected("Rule $ruleId 'explains' entry is not a string")
            }
            prim.content
        }
        if (ids.isNotEmpty() && contribution != Contribution.INNOCENT) {
            throw BundleRejected("Rule $ruleId has 'explains' but is not an innocent rule")
        }
        return ids
    }

    /** The scalar entries of an array value, e.g. the choices of an `in` operator. */
    private fun JsonObject.primitiveList(key: String, ruleId: String): List<String> =
        (this[key] as? JsonArray)?.map { primitiveString(it, ruleId) }
            ?: throw BundleRejected("Rule $ruleId '$key' is not an array")

    private fun JsonObject.childList(key: String, ruleId: String): List<JsonObject> =
        (this[key] as? JsonArray)?.map {
            it as? JsonObject ?: throw BundleRejected("Rule $ruleId '$key' entry is not an object")
        } ?: throw BundleRejected("Rule $ruleId '$key' is not an array")

    private fun JsonObject.childObject(key: String, ruleId: String): JsonObject =
        this[key] as? JsonObject ?: throw BundleRejected("Rule $ruleId '$key' is not an object")

    private fun JsonObject.longOp(key: String, ruleId: String): Long =
        this[key]?.jsonPrimitive?.longOrNull
            ?: throw BundleRejected("Rule $ruleId '$key' is not an integer")

    private fun parseSeverity(raw: String?, ruleId: String): Severity =
        when (raw?.lowercase()) {
            "low" -> Severity.LOW
            "medium" -> Severity.MEDIUM
            "high" -> Severity.HIGH
            "critical" -> Severity.CRITICAL
            else -> throw BundleRejected("Rule $ruleId has unknown severity '$raw'")
        }

    private fun parseContribution(raw: String?, ruleId: String): Contribution =
        when (raw?.lowercase()) {
            "confirm" -> Contribution.CONFIRM
            "strong" -> Contribution.STRONG
            "risk" -> Contribution.RISK
            "innocent" -> Contribution.INNOCENT
            else -> throw BundleRejected("Rule $ruleId has unknown contribution '$raw'")
        }

    private class NodeCounter(private val max: Int) {
        private var seen = 0
        fun count() {
            if (++seen > max) throw BundleRejected("Rule exceeds $max condition nodes")
        }
    }
}
