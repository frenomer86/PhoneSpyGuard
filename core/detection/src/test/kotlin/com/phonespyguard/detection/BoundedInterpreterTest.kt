package com.phonespyguard.detection

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BoundedInterpreterTest {

    private val interpreter = BoundedInterpreter()

    private fun facts(block: Facts.Builder.() -> Unit): Facts =
        Facts.builder().apply(block).build()

    @Test
    fun `eq matches text bool and number`() {
        val f = facts {
            text("app.install_source", "sideload")
            bool("app.accessibility_enabled", true)
            number("app.install_time", 1000L)
        }
        assertTrue(interpreter.matches(Condition.Fact("app.install_source", Operator.Eq(FactValue.Text("sideload"))), f))
        assertTrue(interpreter.matches(Condition.Fact("app.accessibility_enabled", Operator.Eq(FactValue.Bool(true))), f))
        assertTrue(interpreter.matches(Condition.Fact("app.install_time", Operator.Eq(FactValue.Number(1000L))), f))
        assertFalse(interpreter.matches(Condition.Fact("app.install_source", Operator.Eq(FactValue.Text("play"))), f))
    }

    @Test
    fun `eq on a missing fact is false`() {
        val f = facts { }
        assertFalse(interpreter.matches(Condition.Fact("app.missing", Operator.Eq(FactValue.Bool(true))), f))
    }

    @Test
    fun `in matches only listed strings`() {
        val f = facts { text("app.install_source", "unknown") }
        assertTrue(interpreter.matches(Condition.Fact("app.install_source", Operator.In(listOf("sideload", "unknown"))), f))
        assertFalse(interpreter.matches(Condition.Fact("app.install_source", Operator.In(listOf("play"))), f))
    }

    @Test
    fun `contains matches a value inside a text list`() {
        val f = facts { textList("app.permissions", listOf("CAMERA", "RECORD_AUDIO")) }
        assertTrue(interpreter.matches(Condition.Fact("app.permissions", Operator.Contains("CAMERA")), f))
        assertFalse(interpreter.matches(Condition.Fact("app.permissions", Operator.Contains("SMS")), f))
    }

    @Test
    fun `numeric comparisons`() {
        val f = facts { number("app.run_count", 46L) }
        assertTrue(interpreter.matches(Condition.Fact("app.run_count", Operator.Gt(10L)), f))
        assertTrue(interpreter.matches(Condition.Fact("app.run_count", Operator.Gte(46L)), f))
        assertTrue(interpreter.matches(Condition.Fact("app.run_count", Operator.Lt(100L)), f))
        assertTrue(interpreter.matches(Condition.Fact("app.run_count", Operator.Lte(46L)), f))
        assertFalse(interpreter.matches(Condition.Fact("app.run_count", Operator.Gt(46L)), f))
    }

    @Test
    fun `exists checks presence not truthiness`() {
        val f = facts { bool("app.device_admin", false) }
        assertTrue(interpreter.matches(Condition.Fact("app.device_admin", Operator.Exists), f))
        assertFalse(interpreter.matches(Condition.Fact("app.notification_access", Operator.Exists), f))
    }

    @Test
    fun `all any not combine as expected`() {
        val f = facts {
            bool("a", true)
            bool("b", false)
        }
        val a = Condition.Fact("a", Operator.Eq(FactValue.Bool(true)))
        val b = Condition.Fact("b", Operator.Eq(FactValue.Bool(true)))

        assertFalse(interpreter.matches(Condition.All(listOf(a, b)), f))
        assertTrue(interpreter.matches(Condition.Any(listOf(a, b)), f))
        assertTrue(interpreter.matches(Condition.Not(b), f))
        assertTrue(interpreter.matches(Condition.All(listOf(a, Condition.Not(b))), f))
    }

    @Test
    fun `evaluation past the time budget throws`() {
        // A clock that always reports a time past the deadline.
        var t = 0L
        val slow = BoundedInterpreter(
            limits = EvaluationLimits(maxEvaluationMillis = 1),
            clock = { t += 1000; t },
        )
        val deep = Condition.All(listOf(Condition.Fact("a", Operator.Exists)))
        assertThrows(EvaluationBudgetExceeded::class.java) {
            slow.matches(deep, facts { bool("a", true) })
        }
    }
}
