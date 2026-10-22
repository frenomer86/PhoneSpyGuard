package com.phonespyguard.detection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * Serialises [Facts] and snapshots to and from JSON. The change watcher stores
 * the last baseline as JSON (on Android, in the encrypted database) and reads
 * it back next run to diff against; keeping the codec in the core means the
 * same format works in tests and across platforms.
 *
 * Value types are inferred on decode the same way the rule parser infers them:
 * a JSON array is a text list, a boolean is a bool, an integer is a number, and
 * anything else is text.
 */
public object FactsCodec {
    private val json = Json

    public fun encode(facts: Facts): JsonObject = buildJsonObject {
        for (key in facts.keys) {
            when (val value = facts[key]) {
                is FactValue.Text -> put(key, JsonPrimitive(value.value))
                is FactValue.Bool -> put(key, JsonPrimitive(value.value))
                is FactValue.Number -> put(key, JsonPrimitive(value.value))
                is FactValue.TextList -> put(key, buildJsonArray { value.values.forEach { add(JsonPrimitive(it)) } })
                null -> {}
            }
        }
    }

    public fun decode(obj: JsonObject): Facts {
        val builder = Facts.builder()
        for ((key, element) in obj) {
            when (element) {
                is JsonArray -> builder.textList(key, element.map { it.jsonPrimitive.content })
                is JsonPrimitive -> {
                    val prim = element
                    when {
                        prim.booleanOrNull != null -> builder.bool(key, prim.boolean)
                        prim.longOrNull != null -> builder.number(key, prim.long)
                        else -> builder.text(key, prim.content)
                    }
                }
                else -> {}
            }
        }
        return builder.build()
    }

    public fun encodeSnapshot(snapshot: Map<String, Facts>): String {
        val root = buildJsonObject {
            for ((subject, facts) in snapshot) put(subject, encode(facts))
        }
        return json.encodeToString(JsonObject.serializer(), root)
    }

    public fun decodeSnapshot(text: String): Map<String, Facts> {
        val root = json.parseToJsonElement(text).jsonObject
        return root.mapValues { (_, element) -> decode(element.jsonObject) }
    }

    // Small helpers so call sites read cleanly.
    private val JsonPrimitive.boolean: Boolean get() = booleanOrNull == true
    private val JsonPrimitive.long: Long get() = longOrNull ?: 0L
}
