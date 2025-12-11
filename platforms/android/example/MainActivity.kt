/**
 * PubkyNoise Android Example
 *
 * This example demonstrates how to use the PubkyNoise library for secure
 * communication using the Noise Protocol Framework.
 *
 * Features demonstrated:
 * - Manager setup and configuration
 * - Complete 3-step IK handshake
 * - State persistence across app lifecycle
 * - Encryption and decryption
 * - Connection status tracking
 * - Comprehensive error handling
 * - Multiple session management
 *
 * IMPORTANT: This example uses placeholder values for seeds and public keys.
 * In production, replace these with real cryptographic material.
 */
package com.pubky.noise.example

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.pubky.noise.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Main activity demonstrating PubkyNoise integration.
 *
 * The Noise Protocol uses a 3-step handshake:
 * 1. Client calls initiate_connection() to get first message
 * 2. Client sends first message to server, server responds
 * 3. Client calls complete_connection() with server response
 *
 * After handshake, both parties can encrypt/decrypt messages.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PubkyNoiseExample"
        private const val PREFS_NAME = "pubky_noise_state"
        private const val KEY_SESSION_STATE = "session_state"
    }

    // Noise manager instance - handles all cryptographic operations
    private var manager: FfiNoiseManager? = null

    // Current session ID (hex string) - null if not connected
    private var sessionId: String? = null

    // Temporary session ID during handshake (before completion)
    private var pendingSessionId: String? = null

    // First handshake message to send to server
    private var pendingFirstMessage: ByteArray? = null

    // SharedPreferences for persisting state
    private lateinit var prefs: SharedPreferences

    // =========================================================================
    // Lifecycle Methods
    // =========================================================================

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Setup the Noise manager
        setupNoiseManager()

        // Try to restore previous session state
        restoreState()

        // If no restored session, start a new connection
        if (sessionId == null) {
            initiateConnection()
        }
    }

    /**
     * Called when the activity is paused (app goes to background).
     * CRITICAL: Save session state to survive app suspension.
     */
    override fun onPause() {
        super.onPause()
        saveState()
    }

    /**
     * Called when the activity resumes.
     * Restore state if needed.
     */
    override fun onResume() {
        super.onResume()
        // State is restored in onCreate, but you can refresh status here
        sessionId?.let { sid ->
            val status = manager?.getStatus(sid)
            Log.d(TAG, "Session status on resume: $status")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Clean up sessions if needed
        sessionId?.let { sid ->
            manager?.removeSession(sid)
        }
    }

    // =========================================================================
    // Setup and Configuration
    // =========================================================================

    /**
     * Initialize the Noise manager with configuration.
     *
     * Configuration options:
     * - autoReconnect: Enable automatic reconnection attempts
     * - maxReconnectAttempts: Maximum number of retry attempts
     * - reconnectDelayMs: Initial delay between retries (exponential backoff)
     * - batterySaver: Reduce background activity for battery optimization
     * - chunkSize: Size of chunks for large message streaming (32KB default)
     */
    private fun setupNoiseManager() {
        try {
            // Configure for mobile use
            val config = FfiMobileConfig(
                autoReconnect = true,
                maxReconnectAttempts = 5u,
                reconnectDelayMs = 1000uL,
                batterySaver = false,
                chunkSize = 32768uL  // 32KB chunks for mobile networks
            )

            // Client seed - REPLACE WITH REAL CRYPTOGRAPHIC SEED
            // In production, derive this from secure storage (e.g., Android Keystore)
            val clientSeed = ByteArray(32) { index -> index.toByte() }

            // Device identifier for key derivation
            val deviceId = "android-device-${android.os.Build.MODEL}".toByteArray()

            // Key identifier
            val keyId = "my-app-key-id"

            // Create the manager in client mode
            manager = FfiNoiseManager.newClient(
                config = config,
                clientSeed = clientSeed.toList(),
                clientKid = keyId,
                deviceId = deviceId.toList()
            )

            Log.i(TAG, "Noise manager created successfully")

        } catch (e: FfiNoiseError) {
            handleError("Failed to create manager", e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error creating manager: ${e.message}", e)
        }
    }

    // =========================================================================
    // Handshake Flow (3-Step Process)
    // =========================================================================

    /**
     * Step 1: Initiate the connection.
     *
     * This creates the first handshake message to send to the server.
     * The message contains encrypted identity information.
     */
    private fun initiateConnection() {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Server's static public key - REPLACE WITH REAL SERVER KEY
                // In production, obtain this through secure key exchange or configuration
                val serverPk = ByteArray(32) { 0x02.toByte() }  // Placeholder

                // Optional server hint for routing (can be null)
                val serverHint: String? = null

                // Step 1: Initiate connection - this returns the first message
                val result = mgr.initiateConnection(
                    serverPk = serverPk.toList(),
                    hint = serverHint
                )

                // Store pending handshake data
                pendingSessionId = result.sessionId
                pendingFirstMessage = result.firstMessage.toByteArray()

                Log.i(TAG, "Handshake initiated, temp session: ${result.sessionId}")
                Log.d(TAG, "First message size: ${result.firstMessage.size} bytes")

                // ============================================================
                // Step 2: Send firstMessage to server and receive response
                // ============================================================
                // Send the first message to the server over your network transport
                // This example uses URLConnection, but you can use OkHttp, Retrofit, etc.
                try {
                    val serverResponse = sendToServer(result.firstMessage.toByteArray())
                    
                    withContext(Dispatchers.Main) {
                        // Step 3: Complete the connection with server response
                        completeConnection(serverResponse)
                    }
                } catch (e: NetworkException) {
                    withContext(Dispatchers.Main) {
                        handleError("Network transport failed", FfiNoiseError.Network(e.message ?: "Unknown network error"))
                    }
                }

            } catch (e: FfiNoiseError) {
                handleError("Failed to initiate connection", e)
            }
        }
    }

    /**
     * Step 3: Complete the connection after receiving server response.
     *
     * Call this method after your network layer receives the server's
     * handshake response.
     *
     * @param serverResponse The handshake response bytes from the server
     */
    fun completeConnection(serverResponse: ByteArray) {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return
        }

        val tempId = pendingSessionId ?: run {
            Log.e(TAG, "No pending handshake to complete")
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Complete the handshake
                val finalSessionId = mgr.completeConnection(
                    sessionId = tempId,
                    serverResponse = serverResponse.toList()
                )

                withContext(Dispatchers.Main) {
                    // Store the final session ID
                    sessionId = finalSessionId
                    pendingSessionId = null
                    pendingFirstMessage = null

                    Log.i(TAG, "Connection complete! Session ID: $finalSessionId")

                    // Check connection status
                    val status = mgr.getStatus(finalSessionId)
                    Log.d(TAG, "Connection status: $status")

                    // Now the session is ready for encryption/decryption
                    onConnectionEstablished(finalSessionId)
                }

            } catch (e: FfiNoiseError) {
                handleError("Failed to complete connection", e)
            }
        }
    }

    /**
     * Called when connection is successfully established.
     * Override this to handle connection success in your app.
     */
    private fun onConnectionEstablished(sessionId: String) {
        Log.i(TAG, "Session established: $sessionId")

        // Example: Encrypt and send a welcome message
        // encryptAndSend("Hello, server!")
    }

    // =========================================================================
    // Encryption and Decryption
    // =========================================================================

    /**
     * Encrypt a message using the established session.
     *
     * @param plaintext The message to encrypt (UTF-8 string)
     * @return Encrypted bytes, or null on error
     */
    fun encryptMessage(plaintext: String): ByteArray? {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return null
        }

        val sid = sessionId ?: run {
            Log.e(TAG, "No active session")
            return null
        }

        return try {
            val data = plaintext.toByteArray(Charsets.UTF_8)
            val ciphertext = mgr.encrypt(
                sessionId = sid,
                plaintext = data.toList()
            )

            Log.d(TAG, "Encrypted ${data.size} bytes -> ${ciphertext.size} bytes")
            ciphertext.toByteArray()

        } catch (e: FfiNoiseError) {
            handleError("Encryption failed", e)
            null
        }
    }

    /**
     * Encrypt raw bytes using the established session.
     *
     * @param data The bytes to encrypt
     * @return Encrypted bytes, or null on error
     */
    fun encryptBytes(data: ByteArray): ByteArray? {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return null
        }

        val sid = sessionId ?: run {
            Log.e(TAG, "No active session")
            return null
        }

        return try {
            val ciphertext = mgr.encrypt(
                sessionId = sid,
                plaintext = data.toList()
            )

            Log.d(TAG, "Encrypted ${data.size} bytes -> ${ciphertext.size} bytes")
            ciphertext.toByteArray()

        } catch (e: FfiNoiseError) {
            handleError("Encryption failed", e)
            null
        }
    }

    /**
     * Decrypt a message using the established session.
     *
     * @param ciphertext The encrypted bytes to decrypt
     * @return Decrypted string, or null on error
     */
    fun decryptMessage(ciphertext: ByteArray): String? {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return null
        }

        val sid = sessionId ?: run {
            Log.e(TAG, "No active session")
            return null
        }

        return try {
            val plaintext = mgr.decrypt(
                sessionId = sid,
                ciphertext = ciphertext.toList()
            )

            val message = String(plaintext.toByteArray(), Charsets.UTF_8)
            Log.d(TAG, "Decrypted ${ciphertext.size} bytes -> ${plaintext.size} bytes")
            message

        } catch (e: FfiNoiseError) {
            handleError("Decryption failed", e)
            null
        }
    }

    /**
     * Decrypt raw bytes using the established session.
     *
     * @param ciphertext The encrypted bytes to decrypt
     * @return Decrypted bytes, or null on error
     */
    fun decryptBytes(ciphertext: ByteArray): ByteArray? {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return null
        }

        val sid = sessionId ?: run {
            Log.e(TAG, "No active session")
            return null
        }

        return try {
            val plaintext = mgr.decrypt(
                sessionId = sid,
                ciphertext = ciphertext.toList()
            )

            Log.d(TAG, "Decrypted ${ciphertext.size} bytes -> ${plaintext.size} bytes")
            plaintext.toByteArray()

        } catch (e: FfiNoiseError) {
            handleError("Decryption failed", e)
            null
        }
    }

    // =========================================================================
    // Streaming / Large Message Handling
    // =========================================================================

    /**
     * Encrypt a large message using streaming/chunking.
     *
     * For messages larger than the configured chunk size, the library
     * automatically handles chunking. This method demonstrates handling
     * large messages (e.g., files, images).
     *
     * @param data Large data to encrypt (can be > 64KB)
     * @param onProgress Optional callback for progress tracking
     * @return Encrypted chunks, or null on error
     */
    fun encryptStreaming(
        data: ByteArray,
        onProgress: ((Int, Int) -> Unit)? = null
    ): List<ByteArray>? {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return null
        }

        val sid = sessionId ?: run {
            Log.e(TAG, "No active session")
            return null
        }

        return try {
            // Get chunk size from config (default is 32KB for mobile)
            val chunkSize = 32768 // Default mobile chunk size
            val chunks = mutableListOf<ByteArray>()

            // Split large message into chunks
            var offset = 0
            var chunkIndex = 0

            while (offset < data.size) {
                val remaining = data.size - offset
                val currentChunkSize = minOf(chunkSize, remaining)
                val chunk = data.sliceArray(offset until offset + currentChunkSize)

                // Encrypt each chunk
                val encryptedChunk = mgr.encrypt(
                    sessionId = sid,
                    plaintext = chunk.toList()
                )

                chunks.add(encryptedChunk.toByteArray())
                offset += currentChunkSize
                chunkIndex++

                // Report progress
                onProgress?.invoke(offset, data.size)
                Log.d(TAG, "Encrypted chunk $chunkIndex: $currentChunkSize bytes")
            }

            Log.i(TAG, "Streaming encryption complete: ${data.size} bytes -> ${chunks.size} chunks")
            chunks

        } catch (e: FfiNoiseError) {
            handleError("Streaming encryption failed", e)
            null
        }
    }

    /**
     * Decrypt large message chunks and reassemble.
     *
     * This method takes encrypted chunks and reassembles them into
     * the original message.
     *
     * @param chunks List of encrypted chunks to decrypt
     * @param onProgress Optional callback for progress tracking
     * @return Reassembled decrypted data, or null on error
     */
    fun decryptStreaming(
        chunks: List<ByteArray>,
        onProgress: ((Int, Int) -> Unit)? = null
    ): ByteArray? {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return null
        }

        val sid = sessionId ?: run {
            Log.e(TAG, "No active session")
            return null
        }

        return try {
            val decryptedChunks = mutableListOf<ByteArray>()

            // Decrypt each chunk
            chunks.forEachIndexed { index, chunk ->
                val decrypted = mgr.decrypt(
                    sessionId = sid,
                    ciphertext = chunk.toList()
                )

                decryptedChunks.add(decrypted.toByteArray())
                onProgress?.invoke(index + 1, chunks.size)
                Log.d(TAG, "Decrypted chunk ${index + 1}/${chunks.size}")
            }

            // Reassemble all chunks
            val totalSize = decryptedChunks.sumOf { it.size }
            val result = ByteArray(totalSize)
            var offset = 0

            decryptedChunks.forEach { chunk ->
                chunk.copyInto(result, offset)
                offset += chunk.size
            }

            Log.i(TAG, "Streaming decryption complete: ${chunks.size} chunks -> $totalSize bytes")
            result

        } catch (e: FfiNoiseError) {
            handleError("Streaming decryption failed", e)
            null
        }
    }

    /**
     * Example: Encrypt and send a large file.
     *
     * This demonstrates how to handle large data (e.g., images, files)
     * by encrypting in chunks and sending over the network.
     *
     * @param fileData The file data to encrypt and send
     */
    fun encryptAndSendLargeFile(fileData: ByteArray) {
        lifecycleScope.launch(Dispatchers.IO) {
            // Encrypt with progress tracking
            val chunks = encryptStreaming(fileData) { current, total ->
                val progress = (current * 100 / total)
                Log.d(TAG, "Encryption progress: $progress%")
            }

            if (chunks != null) {
                // Send chunks over network
                chunks.forEachIndexed { index, chunk ->
                    try {
                        // In production, send each chunk to server
                        // val response = sendToServer(chunk)
                        Log.d(TAG, "Would send chunk ${index + 1}/${chunks.size} (${chunk.size} bytes)")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to send chunk $index: ${e.message}")
                    }
                }
            }
        }
    }

    /**
     * Configure chunk size based on network conditions.
     *
     * Use smaller chunks for poor networks, larger for good networks.
     *
     * @param networkQuality "poor", "good", or "excellent"
     */
    fun configureChunkSizeForNetwork(networkQuality: String) {
        val chunkSize = when (networkQuality.lowercase()) {
            "poor" -> 16384uL      // 16KB - Battery saver / poor network
            "good" -> 32768uL      // 32KB - Default mobile (balanced)
            "excellent" -> 65536uL // 64KB - Performance mode
            else -> 32768uL        // Default
        }

        Log.i(TAG, "Configuring chunk size: $chunkSize bytes for $networkQuality network")
        // Note: Chunk size is set in MobileConfig when creating the manager
        // This is just for demonstration - in production, recreate manager with new config
    }

    // =========================================================================
    // State Persistence
    // =========================================================================

    /**
     * Save session state to SharedPreferences.
     *
     * CRITICAL: Call this before app suspension to preserve session state.
     * Without this, you'll need to re-establish the connection on resume.
     */
    private fun saveState() {
        val mgr = manager ?: return
        val sid = sessionId ?: return

        try {
            val state = mgr.saveState(sid)

            // Serialize state to JSON
            val json = JSONObject().apply {
                put("session_id", state.sessionId)
                put("peer_static_pk", state.peerStaticPk.joinToString(","))
                put("write_counter", state.writeCounter)
                put("read_counter", state.readCounter)
                put("status", state.status.name)
            }

            prefs.edit()
                .putString(KEY_SESSION_STATE, json.toString())
                .apply()

            Log.d(TAG, "State saved for session: ${state.sessionId}")

        } catch (e: FfiNoiseError) {
            handleError("Failed to save state", e)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to serialize state: ${e.message}", e)
        }
    }

    /**
     * Restore session state from SharedPreferences.
     *
     * Call this on app resume to restore the previous session.
     * Note: This restores metadata only. The actual Noise transport
     * may need to be re-established depending on your use case.
     */
    private fun restoreState() {
        val mgr = manager ?: return

        try {
            val jsonStr = prefs.getString(KEY_SESSION_STATE, null) ?: return
            val json = JSONObject(jsonStr)

            // Parse state from JSON
            val peerPkStr = json.getString("peer_static_pk")
            val peerPkList = peerPkStr.split(",").map { it.trim().toUByte() }

            val statusStr = json.getString("status")
            val status = when (statusStr) {
                "CONNECTED" -> FfiConnectionStatus.CONNECTED
                "RECONNECTING" -> FfiConnectionStatus.RECONNECTING
                "DISCONNECTED" -> FfiConnectionStatus.DISCONNECTED
                else -> FfiConnectionStatus.ERROR
            }

            val state = FfiSessionState(
                sessionId = json.getString("session_id"),
                peerStaticPk = peerPkList,
                writeCounter = json.getLong("write_counter").toULong(),
                readCounter = json.getLong("read_counter").toULong(),
                status = status
            )

            mgr.restoreState(state)
            sessionId = state.sessionId

            Log.i(TAG, "State restored for session: ${state.sessionId}")

        } catch (e: FfiNoiseError) {
            handleError("Failed to restore state", e)
            // Clear corrupted state
            prefs.edit().remove(KEY_SESSION_STATE).apply()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to deserialize state: ${e.message}", e)
            // Clear corrupted state
            prefs.edit().remove(KEY_SESSION_STATE).apply()
        }
    }

    // =========================================================================
    // Connection Status Management
    // =========================================================================

    /**
     * Get the current connection status.
     *
     * @return Current status, or null if no session
     */
    fun getConnectionStatus(): FfiConnectionStatus? {
        val mgr = manager ?: return null
        val sid = sessionId ?: return null

        return try {
            mgr.getStatus(sid)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get status: ${e.message}")
            null
        }
    }

    /**
     * Update the connection status.
     *
     * Call this when your network layer detects status changes.
     *
     * @param status The new connection status
     */
    fun setConnectionStatus(status: FfiConnectionStatus) {
        val mgr = manager ?: return
        val sid = sessionId ?: return

        try {
            mgr.setStatus(sid, status)
            Log.d(TAG, "Status updated to: $status")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set status: ${e.message}")
        }
    }

    // =========================================================================
    // Multiple Session Management
    // =========================================================================

    /**
     * List all active sessions.
     *
     * @return List of session IDs (hex strings)
     */
    fun listSessions(): List<String> {
        val mgr = manager ?: return emptyList()
        return mgr.listSessions()
    }

    /**
     * Remove a session by ID.
     *
     * Call this to clean up sessions that are no longer needed.
     *
     * @param sessionIdToRemove The session ID to remove
     */
    fun removeSession(sessionIdToRemove: String) {
        val mgr = manager ?: return
        mgr.removeSession(sessionIdToRemove)
        Log.d(TAG, "Session removed: $sessionIdToRemove")

        // Clear saved state if this was the active session
        if (sessionIdToRemove == sessionId) {
            sessionId = null
            prefs.edit().remove(KEY_SESSION_STATE).apply()
        }
    }

    // =========================================================================
    // Network Transport Integration
    // =========================================================================

    /**
     * Send data to server over HTTP/HTTPS and receive response.
     *
     * This is an example implementation using URLConnection. In production,
     * you might use OkHttp, Retrofit, or another HTTP client library.
     *
     * @param data The data to send (handshake message)
     * @return Server response bytes
     * @throws NetworkException if network operation fails
     */
    private suspend fun sendToServer(data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        // REPLACE WITH YOUR ACTUAL SERVER URL
        val serverUrl = "https://your-server.com/api/noise/handshake"
        
        try {
            val url = java.net.URL(serverUrl)
            val connection = url.openConnection() as java.net.HttpURLConnection
            
            // Configure connection
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/octet-stream")
            connection.setRequestProperty("Content-Length", data.size.toString())
            connection.doOutput = true
            connection.connectTimeout = 10000 // 10 seconds
            connection.readTimeout = 30000 // 30 seconds
            
            // Send data
            connection.outputStream.use { output ->
                output.write(data)
                output.flush()
            }
            
            // Check response code
            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                throw NetworkException("Server returned error code: $responseCode")
            }
            
            // Read response
            val response = connection.inputStream.use { input ->
                input.readBytes()
            }
            
            Log.d(TAG, "Network request successful: ${data.size} bytes sent, ${response.size} bytes received")
            response
            
        } catch (e: java.net.SocketTimeoutException) {
            throw NetworkException("Connection timeout", e)
        } catch (e: java.net.UnknownHostException) {
            throw NetworkException("Unknown host: $serverUrl", e)
        } catch (e: java.io.IOException) {
            throw NetworkException("IO error: ${e.message}", e)
        } catch (e: Exception) {
            throw NetworkException("Unexpected error: ${e.message}", e)
        }
    }

    /**
     * Custom exception for network errors.
     */
    private inner class NetworkException(message: String, cause: Throwable? = null) : Exception(message, cause)

    // =========================================================================
    // Battery Optimization Examples
    // =========================================================================

    /**
     * Configure manager for battery optimization.
     *
     * Use this when battery level is low or device is in power saver mode.
     * Battery saver mode reduces background activity and uses smaller chunks.
     */
    fun configureBatterySaverMode() {
        val mgr = manager ?: run {
            Log.e(TAG, "Manager not initialized")
            return
        }

        Log.i(TAG, "Switching to battery saver mode")
        // Note: In production, you would recreate the manager with new config
        // This example shows the configuration values

        val batterySaverConfig = FfiMobileConfig(
            autoReconnect = false,        // Disable auto-reconnect to save battery
            maxReconnectAttempts = 1u,     // Minimal retry attempts
            reconnectDelayMs = 2000uL,     // Longer delay between retries
            batterySaver = true,           // Enable battery saver
            chunkSize = 16384uL            // Smaller chunks (16KB) for less memory/CPU
        )

        Log.d(TAG, "Battery saver config:")
        Log.d(TAG, "  autoReconnect: ${batterySaverConfig.autoReconnect}")
        Log.d(TAG, "  maxReconnectAttempts: ${batterySaverConfig.maxReconnectAttempts}")
        Log.d(TAG, "  reconnectDelayMs: ${batterySaverConfig.reconnectDelayMs}")
        Log.d(TAG, "  batterySaver: ${batterySaverConfig.batterySaver}")
        Log.d(TAG, "  chunkSize: ${batterySaverConfig.chunkSize} bytes")

        // In production: Recreate manager with battery saver config
        // manager = FfiNoiseManager.newClient(..., batterySaverConfig)
    }

    /**
     * Configure manager for performance mode.
     *
     * Use this when battery is high and network is good.
     * Performance mode enables aggressive retries and larger chunks.
     */
    fun configurePerformanceMode() {
        Log.i(TAG, "Switching to performance mode")

        val performanceConfig = FfiMobileConfig(
            autoReconnect = true,          // Enable auto-reconnect
            maxReconnectAttempts = 10u,     // Aggressive retry attempts
            reconnectDelayMs = 100uL,      // Quick retry
            batterySaver = false,          // Disable battery saver
            chunkSize = 65536uL            // Larger chunks (64KB) for better throughput
        )

        Log.d(TAG, "Performance config:")
        Log.d(TAG, "  autoReconnect: ${performanceConfig.autoReconnect}")
        Log.d(TAG, "  maxReconnectAttempts: ${performanceConfig.maxReconnectAttempts}")
        Log.d(TAG, "  reconnectDelayMs: ${performanceConfig.reconnectDelayMs}")
        Log.d(TAG, "  batterySaver: ${performanceConfig.batterySaver}")
        Log.d(TAG, "  chunkSize: ${performanceConfig.chunkSize} bytes")
    }

    /**
     * Example: Switch configuration based on battery level.
     *
     * Monitor battery level and adjust configuration accordingly.
     */
    fun updateConfigBasedOnBatteryLevel() {
        // In production, get actual battery level from BatteryManager
        // val batteryLevel = getBatteryLevel() // 0-100

        // Example battery level (replace with actual reading)
        val batteryLevel = 75 // Example: 75%

        when {
            batteryLevel < 20 -> {
                // Critical battery - use aggressive battery saver
                Log.w(TAG, "Battery critical ($batteryLevel%) - enabling battery saver")
                configureBatterySaverMode()
            }
            batteryLevel < 50 -> {
                // Low battery - use conservative settings
                Log.i(TAG, "Battery low ($batteryLevel%) - using conservative config")
                val conservativeConfig = FfiMobileConfig(
                    autoReconnect = true,
                    maxReconnectAttempts = 3u,
                    reconnectDelayMs = 1000uL,
                    batterySaver = true,
                    chunkSize = 16384uL
                )
                // Apply conservative config
            }
            else -> {
                // Good battery - use performance mode
                Log.i(TAG, "Battery good ($batteryLevel%) - using performance config")
                configurePerformanceMode()
            }
        }
    }

    /**
     * Example: Monitor power saver mode and adjust configuration.
     *
     * Android's power saver mode should trigger battery optimization.
     */
    fun handlePowerSaverMode(isPowerSaverEnabled: Boolean) {
        if (isPowerSaverEnabled) {
            Log.i(TAG, "Power saver enabled - switching to battery optimization")
            configureBatterySaverMode()
        } else {
            Log.i(TAG, "Power saver disabled - using normal configuration")
            // Use default or performance config
        }
    }

    /**
     * Example: Adjust chunk size based on network and battery.
     *
     * Balance between performance and battery consumption.
     */
    fun optimizeChunkSize(networkQuality: String, batteryLevel: Int) {
        val chunkSize = when {
            batteryLevel < 30 -> 16384uL      // Low battery: small chunks
            networkQuality == "poor" -> 16384uL  // Poor network: small chunks
            networkQuality == "good" && batteryLevel > 50 -> 32768uL  // Good: default
            networkQuality == "excellent" && batteryLevel > 70 -> 65536uL  // Excellent: large chunks
            else -> 32768uL  // Default
        }

        Log.i(TAG, "Optimized chunk size: $chunkSize bytes (network: $networkQuality, battery: $batteryLevel%)")
    }

    // =========================================================================
    // Thread-Safety Examples
    // =========================================================================

    /**
     * Example: Encrypt data from a background thread.
     *
     * The FfiNoiseManager is thread-safe and can be used from any thread.
     * This example shows how to perform encryption operations on a background
     * thread using Kotlin coroutines.
     */
    fun encryptFromBackgroundThread(data: ByteArray) {
        lifecycleScope.launch(Dispatchers.IO) {
            // Background thread operations
            val mgr = manager ?: run {
                Log.e(TAG, "Manager not initialized")
                return@launch
            }

            val sid = sessionId ?: run {
                Log.e(TAG, "No active session")
                return@launch
            }

            try {
                // Encrypt on background thread
                val ciphertext = mgr.encrypt(
                    sessionId = sid,
                    plaintext = data.toList()
                )

                // Switch back to main thread for UI updates
                withContext(Dispatchers.Main) {
                    Log.i(TAG, "Encryption completed on background thread: ${ciphertext.size} bytes")
                    // Update UI or handle result
                }

            } catch (e: FfiNoiseError) {
                withContext(Dispatchers.Main) {
                    handleError("Background encryption failed", e)
                }
            }
        }
    }

    /**
     * Example: Concurrent encryption operations.
     *
     * Multiple encryption operations can be performed concurrently
     * since the manager is thread-safe.
     */
    fun performConcurrentEncryption(messages: List<String>) {
        lifecycleScope.launch(Dispatchers.IO) {
            val mgr = manager ?: return@launch
            val sid = sessionId ?: return@launch

            // Launch multiple concurrent encryption operations
            val encryptionJobs = messages.map { message ->
                async(Dispatchers.IO) {
                    try {
                        val data = message.toByteArray(Charsets.UTF_8)
                        val ciphertext = mgr.encrypt(
                            sessionId = sid,
                            plaintext = data.toList()
                        )
                        Log.d(TAG, "Encrypted: $message -> ${ciphertext.size} bytes")
                        ciphertext.toByteArray()
                    } catch (e: FfiNoiseError) {
                        Log.e(TAG, "Failed to encrypt '$message': ${e.message}")
                        null
                    }
                }
            }

            // Wait for all operations to complete
            val results = encryptionJobs.awaitAll()

            withContext(Dispatchers.Main) {
                val successCount = results.count { it != null }
                Log.i(TAG, "Concurrent encryption complete: $successCount/${messages.size} succeeded")
            }
        }
    }

    /**
     * Example: Thread-safe session access from multiple threads.
     *
     * This demonstrates that the manager can be safely accessed from
     * multiple threads simultaneously.
     */
    fun demonstrateThreadSafeAccess() {
        val mgr = manager ?: return
        val sid = sessionId ?: return

        // Launch operations from multiple threads
        repeat(5) { threadIndex ->
            lifecycleScope.launch(Dispatchers.Default) {
                try {
                    val message = "Message from thread $threadIndex"
                    val data = message.toByteArray(Charsets.UTF_8)

                    // All threads can safely access the manager
                    val ciphertext = mgr.encrypt(
                        sessionId = sid,
                        plaintext = data.toList()
                    )

                    Log.d(TAG, "Thread $threadIndex: Encrypted ${data.size} bytes -> ${ciphertext.size} bytes")

                } catch (e: FfiNoiseError) {
                    Log.e(TAG, "Thread $threadIndex failed: ${e.message}")
                }
            }
        }
    }

    /**
     * Example: Background thread with proper error handling.
     *
     * Shows best practices for using the manager from background threads
     * with proper error handling and thread switching.
     */
    fun backgroundOperationWithErrorHandling(operation: suspend () -> Unit) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                operation()
            } catch (e: FfiNoiseError) {
                // Handle FFI errors
                withContext(Dispatchers.Main) {
                    handleError("Background operation failed", e)
                }
            } catch (e: Exception) {
                // Handle other exceptions
                withContext(Dispatchers.Main) {
                    Log.e(TAG, "Unexpected error in background: ${e.message}", e)
                }
            }
        }
    }

    // =========================================================================
    // Error Handling
    // =========================================================================

    /**
     * Comprehensive error handler for FfiNoiseError.
     *
     * Maps error types to appropriate handling strategies.
     *
     * @param context Description of what operation failed
     * @param error The FfiNoiseError to handle
     */
    private fun handleError(context: String, error: FfiNoiseError) {
        when (error) {
            is FfiNoiseError.Ring -> {
                // Key management error - check seed/key configuration
                Log.e(TAG, "$context: Key error - ${error.message}")
                // Consider: Reset key material, prompt user to reconfigure
            }

            is FfiNoiseError.InvalidPeerKey -> {
                // Invalid server key - may indicate MITM or misconfiguration
                Log.e(TAG, "$context: Invalid peer key - possible security issue!")
                // Consider: Alert user, refuse to connect, verify key through side channel
            }

            is FfiNoiseError.IdentityVerify -> {
                // Identity verification failed - signature mismatch
                Log.e(TAG, "$context: Identity verification failed")
                // Consider: Alert user, connection may be compromised
            }

            is FfiNoiseError.Network -> {
                // Network error - retry may help
                Log.e(TAG, "$context: Network error - ${error.message}")
                // Consider: Retry with backoff, check connectivity
            }

            is FfiNoiseError.Timeout -> {
                // Timeout - operation took too long
                Log.e(TAG, "$context: Timeout - ${error.message}")
                // Consider: Retry with longer timeout, check network conditions
            }

            is FfiNoiseError.Snow -> {
                // Noise protocol error - internal error
                Log.e(TAG, "$context: Protocol error - ${error.message}")
                // Consider: Log for debugging, may need session reset
            }

            is FfiNoiseError.Serde -> {
                // Serialization error - data format issue
                Log.e(TAG, "$context: Serialization error - ${error.message}")
                // Consider: Check data format, may indicate version mismatch
            }

            is FfiNoiseError.Decryption -> {
                // Decryption failed - data may be corrupted or keys out of sync
                Log.e(TAG, "$context: Decryption error - ${error.message}")
                // Consider: May need session reset, check for replay attacks
            }

            is FfiNoiseError.Storage -> {
                // Storage operation failed
                Log.e(TAG, "$context: Storage error - ${error.message}")
                // Consider: Check storage permissions/space
            }

            is FfiNoiseError.Policy -> {
                // Policy violation - rate limiting or other restrictions
                Log.e(TAG, "$context: Policy violation - ${error.message}")
                // Consider: Back off, check if blocked
            }

            is FfiNoiseError.RateLimited -> {
                // Rate limited - wait and retry (v1.0.0)
                Log.e(TAG, "$context: Rate limited - ${error.message}")
                // Consider: Parse retry-after from message, wait before retrying
            }

            is FfiNoiseError.MaxSessionsExceeded -> {
                // Too many sessions for this identity (v1.0.0)
                Log.e(TAG, "$context: Maximum sessions exceeded")
                // Consider: Close old sessions before creating new ones
            }

            is FfiNoiseError.SessionExpired -> {
                // Session expired or not found (v1.0.0)
                Log.e(TAG, "$context: Session expired - ${error.message}")
                // Consider: Re-authenticate, create new session
            }

            is FfiNoiseError.ConnectionReset -> {
                // Connection was reset (v1.0.0)
                Log.e(TAG, "$context: Connection reset - ${error.message}")
                // Consider: Reconnect with exponential backoff
            }

            is FfiNoiseError.RemoteStaticMissing -> {
                // Server static key not available
                Log.e(TAG, "$context: Remote static key missing")
                // Consider: Obtain server key through configuration
            }

            is FfiNoiseError.Pkarr -> {
                // PKARR-related error (if enabled)
                Log.e(TAG, "$context: PKARR error - ${error.message}")
            }

            is FfiNoiseError.Other -> {
                // Unknown/other error
                Log.e(TAG, "$context: Other error - ${error.message}")
            }
        }
    }
}

// =========================================================================
// Extension Functions for Convenience
// =========================================================================

/**
 * Convert List<UByte> to ByteArray
 */
private fun List<UByte>.toByteArray(): ByteArray {
    return ByteArray(size) { this[it].toByte() }
}

/**
 * Convert ByteArray to List<UByte>
 */
private fun ByteArray.toList(): List<UByte> {
    return map { it.toUByte() }
}
