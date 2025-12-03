// PubkyNoiseExample.kt
// Example usage of pubky-noise in Android/Kotlin
// Version: 0.8.0

package com.pubky.noise.example

import com.pubky.noise.*

/**
 * Example: Cold Key Setup and Connection
 *
 * This demonstrates the recommended pattern for Bitkit integration:
 * 1. Derive X25519 key from Ed25519 identity (one-time, cold operation)
 * 2. Use FfiRawNoiseManager for connections
 * 3. Select appropriate pattern based on use case
 */
class PubkyNoiseExample {

    private var manager: FfiRawNoiseManager? = null

    // MARK: - Initialization

    /**
     * Create a new noise manager with default mobile configuration
     */
    fun initialize() {
        val config = FfiMobileConfig(
            autoReconnect = true,
            maxReconnectAttempts = 3u,
            reconnectDelayMs = 1000u,
            batterySaver = true,
            chunkSize = 65535u
        )

        manager = FfiRawNoiseManager(config)
        println("PubkyNoise manager initialized")
    }

    // MARK: - Key Derivation

    /**
     * Derive X25519 session key from Ed25519 identity seed
     *
     * Call this once during device setup. The Ed25519 key can then be stored cold.
     *
     * @param ed25519Seed 32-byte Ed25519 secret key seed
     * @param deviceId Device identifier for derivation context
     * @return Pair of (X25519 secret key, X25519 public key)
     */
    fun deriveNoiseKeypair(ed25519Seed: ByteArray, deviceId: String): Pair<ByteArray, ByteArray> {
        require(ed25519Seed.size == 32) { "Ed25519 seed must be 32 bytes" }

        val context = deviceId.toByteArray(Charsets.UTF_8)

        // Derive X25519 secret key
        val secretKey = ffiDeriveX25519Static(ed25519Seed.toList(), context.toList())

        // Compute public key
        val publicKey = ffiX25519PublicKey(secretKey)

        return Pair(secretKey.toByteArray(), publicKey.toByteArray())
    }

    // MARK: - Connection Patterns

    /**
     * Connect using IK-raw pattern (cold key scenario)
     *
     * Use when:
     * - You have pre-shared the recipient's X25519 key (via pkarr)
     * - Your Ed25519 identity is kept cold
     * - You want identity hiding from passive observers
     *
     * @param localSecretKey Your X25519 secret key (32 bytes)
     * @param serverPublicKey Recipient's X25519 public key (32 bytes)
     * @return HandshakeResult with session ID and first message
     */
    fun connectIKRaw(localSecretKey: ByteArray, serverPublicKey: ByteArray): FfiHandshakeResult {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.initiateIkRaw(
            localSk = localSecretKey.toList(),
            serverPk = serverPublicKey.toList()
        )
    }

    /**
     * Connect anonymously using N pattern
     *
     * Use when:
     * - The sender wants to remain anonymous
     * - The recipient is authenticated by their static key
     * - You don't need mutual authentication
     *
     * @param serverPublicKey Recipient's X25519 public key (32 bytes)
     * @return HandshakeResult with session ID and first message
     */
    fun connectAnonymous(serverPublicKey: ByteArray): FfiHandshakeResult {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.initiateAnonymous(serverPk = serverPublicKey.toList())
    }

    /**
     * Connect ephemerally using NN pattern
     *
     * Use when:
     * - Both parties want to remain anonymous
     * - You have an out-of-band authentication mechanism
     * - Maximum forward secrecy is required
     *
     * @return HandshakeResult with session ID and first message
     */
    fun connectEphemeral(): FfiHandshakeResult {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.initiateEphemeral()
    }

    // MARK: - Server-Side Accept

    /**
     * Accept an IK-raw connection
     */
    fun acceptIKRaw(localSecretKey: ByteArray, firstMessage: ByteArray): FfiAcceptResult {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.acceptIkRaw(
            localSk = localSecretKey.toList(),
            firstMsg = firstMessage.toList()
        )
    }

    /**
     * Accept an anonymous (N pattern) connection
     */
    fun acceptAnonymous(localSecretKey: ByteArray, firstMessage: ByteArray): FfiAcceptResult {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.acceptAnonymous(
            localSk = localSecretKey.toList(),
            firstMsg = firstMessage.toList()
        )
    }

    // MARK: - Encryption/Decryption

    /**
     * Encrypt a message for the given session
     */
    fun encrypt(sessionId: String, plaintext: ByteArray): ByteArray {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.encrypt(sessionId, plaintext.toList()).toByteArray()
    }

    /**
     * Decrypt a message for the given session
     */
    fun decrypt(sessionId: String, ciphertext: ByteArray): ByteArray {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.decrypt(sessionId, ciphertext.toList()).toByteArray()
    }

    // MARK: - Session Management

    /**
     * Save session state for persistence (e.g., app backgrounding)
     */
    fun saveSession(sessionId: String): FfiSessionState {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        return mgr.saveState(sessionId)
    }

    /**
     * Restore a saved session
     */
    fun restoreSession(state: FfiSessionState) {
        val mgr = manager ?: throw IllegalStateException("Manager not initialized")

        mgr.restoreState(state)
    }

    /**
     * List all active sessions
     */
    fun listSessions(): List<String> {
        return manager?.listSessions() ?: emptyList()
    }

    /**
     * Remove a session
     */
    fun removeSession(sessionId: String) {
        manager?.removeSession(sessionId)
    }
}

// MARK: - Extension Helpers

private fun List<UByte>.toByteArray(): ByteArray {
    return ByteArray(size) { this[it].toByte() }
}

private fun ByteArray.toList(): List<UByte> {
    return map { it.toUByte() }
}

// MARK: - Usage Example

/*

// Example: Cold key payment flow

val noise = PubkyNoiseExample()
noise.initialize()

// One-time setup (cold key derivation)
val ed25519Seed = ByteArray(32) { 0x01 } // Your Ed25519 secret
val deviceId = "bitkit-android-1"
val (x25519Sk, x25519Pk) = noise.deriveNoiseKeypair(ed25519Seed, deviceId)

// Store x25519Sk securely in Android Keystore
// Publish x25519Pk to pkarr
// Ed25519 key can now be stored cold

// Later: Connect to recipient
val recipientPk = ByteArray(32) { 0x02 } // From pkarr lookup
val result = noise.connectIKRaw(x25519Sk, recipientPk)
val sessionId = result.sessionId
val firstMsg = result.message

// Send firstMsg over network...
// Receive response...
// Complete handshake...

// Encrypt messages
val ciphertext = noise.encrypt(sessionId, "Hello".toByteArray())

*/

