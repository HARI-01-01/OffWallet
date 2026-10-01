package com.offlinewallet.crypto

import java.security.SecureRandom

object MnemonicManager {
    private val random = SecureRandom()

    /**
     * WP-13: Generates a 24-word BIP-39 mnemonic (simplified for hackathon).
     */
    fun generateMnemonic(): String {
        // Simplified: Pick 24 random words from a mock wordlist
        val wordlist = listOf(
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
            "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
            "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
            "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent"
        )
        return (1..24).map { wordlist[random.nextInt(wordlist.size)] }.joinToString(" ")
    }
}
