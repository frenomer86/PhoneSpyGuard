package com.phonespyguard.evidence

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EvidenceLogTest {

    private fun log(signer: EvidenceSigner = TestSigner()): EvidenceLog {
        var t = 1_000L
        return EvidenceLog(signer = signer, clock = { t += 1000; t })
    }

    @Test
    fun `append chains entries and verifies intact`() {
        val log = log()
        log.append(EntryType.FINDING, "Hidden app that can read your screen", mapOf("app" to "com.x"))
        log.append(EntryType.ANSWER, "Owner said: I did not install this")
        log.append(EntryType.CHANGE, "Gained accessibility access", mapOf("app" to "com.x"))

        assertEquals(3, log.size)
        assertEquals(ChainCheck.Intact, log.verify())
        // seq numbering and linking
        val entries = log.all()
        assertEquals(listOf(0L, 1L, 2L), entries.map { it.seq })
        assertEquals(entries[0].entryHash, entries[1].prevHash)
    }

    @Test
    fun `tampering with an entry breaks the chain`() {
        val signer = TestSigner()
        val log = log(signer)
        log.append(EntryType.FINDING, "original summary")
        log.append(EntryType.NOTE, "second")

        val tampered = log.all().toMutableList()
        tampered[0] = tampered[0].copy(summary = "edited summary")

        val check = EvidenceLog.verify(tampered, signer)
        val broken = assertInstanceOf(ChainCheck.Broken::class.java, check)
        assertEquals(0L, broken.atSeq)
    }

    @Test
    fun `deleting a middle entry breaks the chain`() {
        val signer = TestSigner()
        val log = log(signer)
        log.append(EntryType.FINDING, "a")
        log.append(EntryType.NOTE, "b")
        log.append(EntryType.NOTE, "c")

        val withHole = log.all().toMutableList().also { it.removeAt(1) }
        val check = EvidenceLog.verify(withHole, signer)
        assertInstanceOf(ChainCheck.Broken::class.java, check)
    }

    @Test
    fun `reordering entries breaks the chain`() {
        val signer = TestSigner()
        val log = log(signer)
        log.append(EntryType.FINDING, "a")
        log.append(EntryType.NOTE, "b")

        val swapped = log.all().reversed()
        val check = EvidenceLog.verify(swapped, signer)
        assertInstanceOf(ChainCheck.Broken::class.java, check)
    }

    @Test
    fun `a signature from the wrong key fails verification`() {
        val log = log(TestSigner("real"))
        log.append(EntryType.FINDING, "a")
        // Verify against a different key.
        val check = EvidenceLog.verify(log.all(), TestSigner("imposter"))
        assertInstanceOf(ChainCheck.Broken::class.java, check)
    }

    @Test
    fun `export and re-import round-trips and stays verifiable`() {
        val signer = TestSigner()
        val log = log(signer)
        log.append(EntryType.FINDING, "déjà vu; with = and ; punctuation", mapOf("k=1" to "v;2"))
        log.append(EntryType.EXPORT, "owner exported the timeline")

        val exported = log.exportJson()
        val reloaded = EvidenceLog.fromJson(exported)
        assertEquals(2, reloaded.size)
        assertEquals(ChainCheck.Intact, EvidenceLog.verify(reloaded, signer))
    }

    @Test
    fun `details with reserved characters cannot forge field boundaries`() {
        val signer = TestSigner()
        val log = log(signer)
        // A value containing the field separators must not collide with a
        // different field layout after escaping.
        log.append(EntryType.NOTE, "summary", mapOf("a" to "x;b=y"))
        assertEquals(ChainCheck.Intact, log.verify())

        val tampered = log.all().toMutableList()
        tampered[0] = tampered[0].copy(details = mapOf("a" to "x", "b" to "y"))
        assertTrue(EvidenceLog.verify(tampered, signer) is ChainCheck.Broken)
    }
}
