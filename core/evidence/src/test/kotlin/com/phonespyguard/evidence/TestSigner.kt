package com.phonespyguard.evidence

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

/**
 * A test stand-in for the Android Keystore signer, using an in-process Ed25519
 * keypair. On-device the private key lives in hardware and never leaves it; the
 * chain logic under test does not care which signer it is handed.
 */
class TestSigner(override val keyId: String = "test-key") : EvidenceSigner {
    private val keyPair: KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    override fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").run {
            initSign(keyPair.private)
            update(data)
            sign()
        }

    override fun verify(data: ByteArray, signature: ByteArray): Boolean =
        runCatching {
            Signature.getInstance("Ed25519").run {
                initVerify(keyPair.public)
                update(data)
                verify(signature)
            }
        }.getOrDefault(false)
}
