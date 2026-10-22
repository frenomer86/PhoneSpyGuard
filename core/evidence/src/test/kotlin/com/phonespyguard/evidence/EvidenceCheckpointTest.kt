package com.phonespyguard.evidence

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test

class EvidenceCheckpointTest {

    private fun logOf(signer: TestSigner, n: Int): EvidenceLog {
        val log = EvidenceLog(signer)
        repeat(n) { i -> log.append(EntryType.FINDING, "finding $i") }
        return log
    }

    @Test
    fun `checkpoint matches its own chain`() {
        val signer = TestSigner()
        val log = logOf(signer, 3)
        val cp = log.checkpoint()
        assertEquals(3, cp.count)
        assertEquals(
            CheckpointCheck.Ok,
            EvidenceLog.verifyAgainstCheckpoint(log.all(), signer, cp),
        )
    }

    @Test
    fun `truncating the newest entries is caught by the checkpoint`() {
        val signer = TestSigner()
        val log = logOf(signer, 5)
        val cp = log.checkpoint() // count = 5
        // Attacker keeps a shorter, still-internally-valid chain.
        val truncated = log.all().take(3)
        // Plain chain verification still passes on the truncated chain...
        assertEquals(ChainCheck.Intact, EvidenceLog.verify(truncated, signer))
        // ...but the checkpoint notices entries are missing.
        val result = EvidenceLog.verifyAgainstCheckpoint(truncated, signer, cp)
        val mismatch = assertInstanceOf(CheckpointCheck.Mismatch::class.java, result)
        assert(mismatch.reason.contains("deleted"))
    }

    @Test
    fun `appending more after a checkpoint still matches it`() {
        val signer = TestSigner()
        val log = logOf(signer, 2)
        val cp = log.checkpoint()
        log.append(EntryType.NOTE, "later note")
        assertEquals(
            CheckpointCheck.Ok,
            EvidenceLog.verifyAgainstCheckpoint(log.all(), signer, cp),
        )
    }

    @Test
    fun `a checkpoint from another key does not verify`() {
        val signer = TestSigner()
        val attacker = TestSigner("attacker")
        val log = logOf(signer, 2)
        val forged = logOf(attacker, 2).checkpoint()
        val result = EvidenceLog.verifyAgainstCheckpoint(log.all(), signer, forged)
        assertInstanceOf(CheckpointCheck.Mismatch::class.java, result)
    }
}
