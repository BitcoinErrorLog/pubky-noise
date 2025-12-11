/**
 * PubkyNoise iOS Example
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
 * In production, replace these with real cryptographic material from the Keychain.
 */

import Foundation
import PubkyNoise

// MARK: - NoiseManager Class

/**
 * Main class demonstrating PubkyNoise integration for iOS.
 *
 * The Noise Protocol uses a 3-step handshake:
 * 1. Client calls initiateConnection() to get first message
 * 2. Client sends first message to server, server responds
 * 3. Client calls completeConnection() with server response
 *
 * After handshake, both parties can encrypt/decrypt messages.
 */
class NoiseManager {
    
    // MARK: - Properties
    
    /// Noise manager instance - handles all cryptographic operations
    private var manager: FfiNoiseManager?
    
    /// Current session ID (hex string) - nil if not connected
    private(set) var sessionId: String?
    
    /// Temporary session ID during handshake (before completion)
    private var pendingSessionId: String?
    
    /// First handshake message to send to server
    private(set) var pendingFirstMessage: Data?
    
    /// UserDefaults key for state persistence
    private let stateKey = "pubky_noise_session_state"
    
    /// Delegate for connection events (optional)
    weak var delegate: NoiseManagerDelegate?
    
    // MARK: - Initialization
    
    init() {
        setupManager()
        restoreState()
    }
    
    deinit {
        // Clean up sessions
        if let sid = sessionId {
            manager?.removeSession(sessionId: sid)
        }
    }
    
    // MARK: - Setup and Configuration
    
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
    private func setupManager() {
        do {
            // Configure for mobile use
            let config = FfiMobileConfig(
                autoReconnect: true,
                maxReconnectAttempts: 5,
                reconnectDelayMs: 1000,
                batterySaver: false,
                chunkSize: 32768  // 32KB chunks for mobile networks
            )
            
            // Client seed - REPLACE WITH REAL CRYPTOGRAPHIC SEED
            // In production, derive this from Keychain SecureEnclave
            var clientSeed = Data(count: 32)
            for i in 0..<32 {
                clientSeed[i] = UInt8(i)
            }
            
            // Device identifier for key derivation
            let deviceId = "ios-device-\(UIDevice.current.identifierForVendor?.uuidString ?? "unknown")"
                .data(using: .utf8)!
            
            // Key identifier
            let keyId = "my-app-key-id"
            
            // Create the manager in client mode
            manager = try FfiNoiseManager.newClient(
                config: config,
                clientSeed: clientSeed,
                clientKid: keyId,
                deviceId: deviceId
            )
            
            print("[PubkyNoise] Manager created successfully")
            
        } catch let error as FfiNoiseError {
            handleError(context: "Failed to create manager", error: error)
        } catch {
            print("[PubkyNoise] Unexpected error creating manager: \(error)")
        }
    }
    
    // MARK: - Handshake Flow (3-Step Process)
    
    /**
     * Step 1: Initiate the connection.
     *
     * This creates the first handshake message to send to the server.
     * The message contains encrypted identity information.
     *
     * - Parameter serverPublicKey: Server's static X25519 public key (32 bytes)
     * - Parameter hint: Optional server hint for routing
     * - Throws: FfiNoiseError if initiation fails
     * - Returns: The first message to send to the server
     */
    func initiateConnection(serverPublicKey: Data, hint: String? = nil) throws -> Data {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard serverPublicKey.count == 32 else {
            throw NoiseManagerError.invalidKeyLength
        }
        
        // Step 1: Initiate connection - this returns the first message
        let result = try manager.initiateConnection(
            serverPk: serverPublicKey,
            hint: hint
        )
        
        // Store pending handshake data
        pendingSessionId = result.sessionId
        pendingFirstMessage = result.firstMessage
        
        print("[PubkyNoise] Handshake initiated, temp session: \(result.sessionId)")
        print("[PubkyNoise] First message size: \(result.firstMessage.count) bytes")
        
        return result.firstMessage
    }
    
    /**
     * Complete handshake with network transport integration.
     *
     * This method demonstrates the complete flow including network transport.
     * It initiates the connection, sends the first message over the network,
     * and completes the connection with the server response.
     *
     * - Parameter serverPublicKey: Server's static X25519 public key (32 bytes)
     * - Throws: Error if handshake or network operation fails
     * - Returns: The final session ID
     */
    func performHandshakeWithNetwork(serverPublicKey: Data) async throws -> String {
        // Step 1: Initiate connection
        let firstMessage = try initiateConnection(serverPublicKey: serverPublicKey, hint: nil)
        
        // Step 2: Send first message to server and receive response
        let serverResponse = try await sendToServer(data: firstMessage)
        
        // Step 3: Complete connection
        return try completeConnection(serverResponse: serverResponse)
    }
    
    /**
     * Step 3: Complete the connection after receiving server response.
     *
     * Call this method after your network layer receives the server's
     * handshake response.
     *
     * - Parameter serverResponse: The handshake response bytes from the server
     * - Throws: FfiNoiseError if completion fails
     * - Returns: The final session ID
     */
    @discardableResult
    func completeConnection(serverResponse: Data) throws -> String {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard let tempId = pendingSessionId else {
            throw NoiseManagerError.noPendingHandshake
        }
        
        // Complete the handshake
        let finalSessionId = try manager.completeConnection(
            sessionId: tempId,
            serverResponse: serverResponse
        )
        
        // Store the final session ID
        sessionId = finalSessionId
        pendingSessionId = nil
        pendingFirstMessage = nil
        
        print("[PubkyNoise] Connection complete! Session ID: \(finalSessionId)")
        
        // Check connection status
        if let status = manager.getStatus(sessionId: finalSessionId) {
            print("[PubkyNoise] Connection status: \(status)")
        }
        
        // Notify delegate
        delegate?.noiseManager(self, didEstablishSession: finalSessionId)
        
        return finalSessionId
    }
    
    /**
     * Convenience method to perform a complete handshake.
     *
     * This method demonstrates the full flow but requires you to provide
     * a network transport function.
     *
     * - Parameter serverPublicKey: Server's static X25519 public key (32 bytes)
     * - Parameter sendAndReceive: Closure that sends data and returns response
     * - Throws: Error if handshake fails
     * - Returns: The final session ID
     */
    func performHandshake(
        serverPublicKey: Data,
        sendAndReceive: (Data) throws -> Data
    ) throws -> String {
        // Step 1: Initiate
        let firstMessage = try initiateConnection(serverPublicKey: serverPublicKey)
        
        // Step 2: Send and receive (your network transport)
        let serverResponse = try sendAndReceive(firstMessage)
        
        // Step 3: Complete
        return try completeConnection(serverResponse: serverResponse)
    }
    
    /**
     * Network transport function using URLSession.
     *
     * This is an example implementation. In production, you might use
     * Alamofire, URLSession with custom configuration, or another HTTP client.
     *
     * - Parameter data: The data to send (handshake message)
     * - Returns: Server response data
     * - Throws: Error if network operation fails
     */
    func sendToServer(data: Data) async throws -> Data {
        // REPLACE WITH YOUR ACTUAL SERVER URL
        guard let url = URL(string: "https://your-server.com/api/noise/handshake") else {
            throw NoiseManagerError.configurationError("Invalid server URL")
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue("\(data.count)", forHTTPHeaderField: "Content-Length")
        request.httpBody = data
        request.timeoutInterval = 30.0
        
        do {
            let (responseData, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                throw NoiseManagerError.networkError("Invalid response type")
            }
            
            guard (200...299).contains(httpResponse.statusCode) else {
                throw NoiseManagerError.networkError("Server returned error code: \(httpResponse.statusCode)")
            }
            
            print("[PubkyNoise] Network request successful: \(data.count) bytes sent, \(responseData.count) bytes received")
            return responseData
            
        } catch let error as NoiseManagerError {
            throw error
        } catch {
            throw NoiseManagerError.networkError("Network error: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Encryption and Decryption
    
    /**
     * Encrypt a message using the established session.
     *
     * - Parameter message: The string message to encrypt
     * - Throws: FfiNoiseError if encryption fails
     * - Returns: Encrypted bytes
     */
    func encrypt(message: String) throws -> Data {
        guard let data = message.data(using: .utf8) else {
            throw NoiseManagerError.invalidInput
        }
        return try encrypt(data: data)
    }
    
    /**
     * Encrypt raw bytes using the established session.
     *
     * - Parameter data: The bytes to encrypt
     * - Throws: FfiNoiseError if encryption fails
     * - Returns: Encrypted bytes
     */
    func encrypt(data: Data) throws -> Data {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard let sid = sessionId else {
            throw NoiseManagerError.noActiveSession
        }
        
        let ciphertext = try manager.encrypt(sessionId: sid, plaintext: data)
        print("[PubkyNoise] Encrypted \(data.count) bytes -> \(ciphertext.count) bytes")
        return ciphertext
    }
    
    /**
     * Decrypt a message using the established session.
     *
     * - Parameter ciphertext: The encrypted bytes to decrypt
     * - Throws: FfiNoiseError if decryption fails
     * - Returns: Decrypted string
     */
    func decrypt(ciphertext: Data) throws -> String {
        let data = try decryptToData(ciphertext: ciphertext)
        guard let message = String(data: data, encoding: .utf8) else {
            throw NoiseManagerError.invalidOutput
        }
        return message
    }
    
    /**
     * Decrypt raw bytes using the established session.
     *
     * - Parameter ciphertext: The encrypted bytes to decrypt
     * - Throws: FfiNoiseError if decryption fails
     * - Returns: Decrypted bytes
     */
    func decryptToData(ciphertext: Data) throws -> Data {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard let sid = sessionId else {
            throw NoiseManagerError.noActiveSession
        }
        
        let plaintext = try manager.decrypt(sessionId: sid, ciphertext: ciphertext)
        print("[PubkyNoise] Decrypted \(ciphertext.count) bytes -> \(plaintext.count) bytes")
        return plaintext
    }
    
    // MARK: - Streaming / Large Message Handling
    
    /**
     * Encrypt a large message using streaming/chunking.
     *
     * For messages larger than the configured chunk size, you need to
     * manually handle chunking. This method demonstrates handling
     * large messages (e.g., files, images).
     *
     * - Parameter data: Large data to encrypt (can be > 64KB)
     * - Parameter onProgress: Optional callback for progress tracking
     * - Throws: FfiNoiseError if encryption fails
     * - Returns: List of encrypted chunks
     */
    func encryptStreaming(
        data: Data,
        onProgress: ((Int, Int) -> Void)? = nil
    ) throws -> [Data] {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard let sid = sessionId else {
            throw NoiseManagerError.noActiveSession
        }
        
        // Get chunk size from config (default is 32KB for mobile)
        let chunkSize = 32768 // Default mobile chunk size
        var chunks: [Data] = []
        var offset = 0
        var chunkIndex = 0
        
        while offset < data.count {
            let remaining = data.count - offset
            let currentChunkSize = min(chunkSize, remaining)
            let range = offset..<(offset + currentChunkSize)
            let chunk = data.subdata(in: range)
            
            // Encrypt each chunk
            let encryptedChunk = try manager.encrypt(sessionId: sid, plaintext: chunk)
            chunks.append(encryptedChunk)
            
            offset += currentChunkSize
            chunkIndex += 1
            
            // Report progress
            onProgress?(offset, data.count)
            print("[PubkyNoise] Encrypted chunk \(chunkIndex): \(currentChunkSize) bytes")
        }
        
        print("[PubkyNoise] Streaming encryption complete: \(data.count) bytes -> \(chunks.count) chunks")
        return chunks
    }
    
    /**
     * Decrypt large message chunks and reassemble.
     *
     * This method takes encrypted chunks and reassembles them into
     * the original message.
     *
     * - Parameter chunks: Array of encrypted chunks to decrypt
     * - Parameter onProgress: Optional callback for progress tracking
     * - Throws: FfiNoiseError if decryption fails
     * - Returns: Reassembled decrypted data
     */
    func decryptStreaming(
        chunks: [Data],
        onProgress: ((Int, Int) -> Void)? = nil
    ) throws -> Data {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard let sid = sessionId else {
            throw NoiseManagerError.noActiveSession
        }
        
        var decryptedChunks: [Data] = []
        
        // Decrypt each chunk
        for (index, chunk) in chunks.enumerated() {
            let decrypted = try manager.decrypt(sessionId: sid, ciphertext: chunk)
            decryptedChunks.append(decrypted)
            onProgress?(index + 1, chunks.count)
            print("[PubkyNoise] Decrypted chunk \(index + 1)/\(chunks.count)")
        }
        
        // Reassemble all chunks
        var result = Data()
        for chunk in decryptedChunks {
            result.append(chunk)
        }
        
        print("[PubkyNoise] Streaming decryption complete: \(chunks.count) chunks -> \(result.count) bytes")
        return result
    }
    
    /**
     * Example: Encrypt and send a large file.
     *
     * This demonstrates how to handle large data (e.g., images, files)
     * by encrypting in chunks and sending over the network.
     *
     * - Parameter fileData: The file data to encrypt and send
     */
    func encryptAndSendLargeFile(fileData: Data) async throws {
        // Encrypt with progress tracking
        let chunks = try encryptStreaming(fileData) { current, total in
            let progress = (current * 100 / total)
            print("[PubkyNoise] Encryption progress: \(progress)%")
        }
        
        // Send chunks over network
        for (index, chunk) in chunks.enumerated() {
            do {
                // In production, send each chunk to server
                // let response = try await sendToServer(data: chunk)
                print("[PubkyNoise] Would send chunk \(index + 1)/\(chunks.count) (\(chunk.count) bytes)")
            } catch {
                print("[PubkyNoise] Failed to send chunk \(index): \(error.localizedDescription)")
                throw error
            }
        }
    }
    
    /**
     * Configure chunk size based on network conditions.
     *
     * Use smaller chunks for poor networks, larger for good networks.
     *
     * - Parameter networkQuality: "poor", "good", or "excellent"
     */
    func configureChunkSizeForNetwork(_ networkQuality: String) {
        let chunkSize: UInt64 = {
            switch networkQuality.lowercased() {
            case "poor":
                return 16384  // 16KB - Battery saver / poor network
            case "good":
                return 32768  // 32KB - Default mobile (balanced)
            case "excellent":
                return 65536  // 64KB - Performance mode
            default:
                return 32768  // Default
            }
        }()
        
        print("[PubkyNoise] Configuring chunk size: \(chunkSize) bytes for \(networkQuality) network")
        // Note: Chunk size is set in MobileConfig when creating the manager
        // This is just for demonstration - in production, recreate manager with new config
    }
    
    // MARK: - State Persistence
    
    /**
     * Save session state to UserDefaults.
     *
     * CRITICAL: Call this before app suspension to preserve session state.
     * Without this, you'll need to re-establish the connection on resume.
     */
    func saveState() {
        guard let manager = manager, let sid = sessionId else {
            return
        }
        
        do {
            let state = try manager.saveState(sessionId: sid)
            
            // Serialize state to dictionary
            let dict: [String: Any] = [
                "session_id": state.sessionId,
                "peer_static_pk": Array(state.peerStaticPk),
                "write_counter": state.writeCounter,
                "read_counter": state.readCounter,
                "status": statusToString(state.status)
            ]
            
            UserDefaults.standard.set(dict, forKey: stateKey)
            print("[PubkyNoise] State saved for session: \(state.sessionId)")
            
        } catch let error as FfiNoiseError {
            handleError(context: "Failed to save state", error: error)
        } catch {
            print("[PubkyNoise] Failed to save state: \(error)")
        }
    }
    
    /**
     * Restore session state from UserDefaults.
     *
     * Called automatically on initialization.
     * Note: This restores metadata only. The actual Noise transport
     * may need to be re-established depending on your use case.
     */
    private func restoreState() {
        guard let manager = manager else { return }
        
        guard let dict = UserDefaults.standard.dictionary(forKey: stateKey) else {
            return
        }
        
        do {
            guard let sessionIdStr = dict["session_id"] as? String,
                  let peerPkArray = dict["peer_static_pk"] as? [UInt8],
                  let writeCounter = dict["write_counter"] as? UInt64,
                  let readCounter = dict["read_counter"] as? UInt64,
                  let statusStr = dict["status"] as? String else {
                throw NoiseManagerError.invalidState
            }
            
            let state = FfiSessionState(
                sessionId: sessionIdStr,
                peerStaticPk: Data(peerPkArray),
                writeCounter: writeCounter,
                readCounter: readCounter,
                status: stringToStatus(statusStr)
            )
            
            try manager.restoreState(state: state)
            sessionId = state.sessionId
            
            print("[PubkyNoise] State restored for session: \(state.sessionId)")
            
        } catch let error as FfiNoiseError {
            handleError(context: "Failed to restore state", error: error)
            clearSavedState()
        } catch {
            print("[PubkyNoise] Failed to restore state: \(error)")
            clearSavedState()
        }
    }
    
    /**
     * Clear saved state from UserDefaults.
     */
    func clearSavedState() {
        UserDefaults.standard.removeObject(forKey: stateKey)
    }
    
    // MARK: - Connection Status Management
    
    /**
     * Get the current connection status.
     *
     * - Returns: Current status, or nil if no session
     */
    func getConnectionStatus() -> FfiConnectionStatus? {
        guard let manager = manager, let sid = sessionId else {
            return nil
        }
        return manager.getStatus(sessionId: sid)
    }
    
    /**
     * Update the connection status.
     *
     * Call this when your network layer detects status changes.
     *
     * - Parameter status: The new connection status
     */
    func setConnectionStatus(_ status: FfiConnectionStatus) {
        guard let manager = manager, let sid = sessionId else {
            return
        }
        manager.setStatus(sessionId: sid, status: status)
        print("[PubkyNoise] Status updated to: \(status)")
        
        delegate?.noiseManager(self, didChangeStatus: status)
    }
    
    // MARK: - Multiple Session Management
    
    /**
     * List all active sessions.
     *
     * - Returns: List of session IDs (hex strings)
     */
    func listSessions() -> [String] {
        return manager?.listSessions() ?? []
    }
    
    /**
     * Remove a session by ID.
     *
     * Call this to clean up sessions that are no longer needed.
     *
     * - Parameter sessionIdToRemove: The session ID to remove
     */
    func removeSession(_ sessionIdToRemove: String) {
        manager?.removeSession(sessionId: sessionIdToRemove)
        print("[PubkyNoise] Session removed: \(sessionIdToRemove)")
        
        // Clear saved state if this was the active session
        if sessionIdToRemove == sessionId {
            sessionId = nil
            clearSavedState()
        }
    }
    
    /**
     * Check if there is an active session.
     */
    var hasActiveSession: Bool {
        return sessionId != nil
    }
    
    // MARK: - Battery Optimization Examples
    
    /**
     * Configure manager for battery optimization.
     *
     * Use this when battery level is low or device is in low power mode.
     * Battery saver mode reduces background activity and uses smaller chunks.
     */
    func configureBatterySaverMode() {
        print("[PubkyNoise] Switching to battery saver mode")
        // Note: In production, you would recreate the manager with new config
        // This example shows the configuration values
        
        let batterySaverConfig = FfiMobileConfig(
            autoReconnect: false,        // Disable auto-reconnect to save battery
            maxReconnectAttempts: 1,
            reconnectDelayMs: 2000,      // Longer delay between retries
            batterySaver: true,           // Enable battery saver
            chunkSize: 16384             // Smaller chunks (16KB) for less memory/CPU
        )
        
        print("[PubkyNoise] Battery saver config:")
        print("[PubkyNoise]   autoReconnect: \(batterySaverConfig.autoReconnect)")
        print("[PubkyNoise]   maxReconnectAttempts: \(batterySaverConfig.maxReconnectAttempts)")
        print("[PubkyNoise]   reconnectDelayMs: \(batterySaverConfig.reconnectDelayMs)")
        print("[PubkyNoise]   batterySaver: \(batterySaverConfig.batterySaver)")
        print("[PubkyNoise]   chunkSize: \(batterySaverConfig.chunkSize) bytes")
        
        // In production: Recreate manager with battery saver config
        // manager = try FfiNoiseManager.newClient(..., batterySaverConfig)
    }
    
    /**
     * Configure manager for performance mode.
     *
     * Use this when battery is high and network is good.
     * Performance mode enables aggressive retries and larger chunks.
     */
    func configurePerformanceMode() {
        print("[PubkyNoise] Switching to performance mode")
        
        let performanceConfig = FfiMobileConfig(
            autoReconnect: true,          // Enable auto-reconnect
            maxReconnectAttempts: 10,     // Aggressive retry attempts
            reconnectDelayMs: 100,        // Quick retry
            batterySaver: false,          // Disable battery saver
            chunkSize: 65536              // Larger chunks (64KB) for better throughput
        )
        
        print("[PubkyNoise] Performance config:")
        print("[PubkyNoise]   autoReconnect: \(performanceConfig.autoReconnect)")
        print("[PubkyNoise]   maxReconnectAttempts: \(performanceConfig.maxReconnectAttempts)")
        print("[PubkyNoise]   reconnectDelayMs: \(performanceConfig.reconnectDelayMs)")
        print("[PubkyNoise]   batterySaver: \(performanceConfig.batterySaver)")
        print("[PubkyNoise]   chunkSize: \(performanceConfig.chunkSize) bytes")
    }
    
    /**
     * Example: Switch configuration based on battery level.
     *
     * Monitor battery level and adjust configuration accordingly.
     */
    func updateConfigBasedOnBatteryLevel() {
        // In production, get actual battery level from UIDevice
        // let batteryLevel = UIDevice.current.batteryLevel * 100 // 0-100
        
        // Example battery level (replace with actual reading)
        let batteryLevel = 75 // Example: 75%
        
        switch batteryLevel {
        case 0..<20:
            // Critical battery - use aggressive battery saver
            print("[PubkyNoise] Battery critical (\(batteryLevel)%) - enabling battery saver")
            configureBatterySaverMode()
        case 20..<50:
            // Low battery - use conservative settings
            print("[PubkyNoise] Battery low (\(batteryLevel)%) - using conservative config")
            let conservativeConfig = FfiMobileConfig(
                autoReconnect: true,
                maxReconnectAttempts: 3,
                reconnectDelayMs: 1000,
                batterySaver: true,
                chunkSize: 16384
            )
            // Apply conservative config
        default:
            // Good battery - use performance mode
            print("[PubkyNoise] Battery good (\(batteryLevel)%) - using performance config")
            configurePerformanceMode()
        }
    }
    
    /**
     * Example: Monitor low power mode and adjust configuration.
     *
     * iOS's low power mode should trigger battery optimization.
     */
    func handleLowPowerMode(_ isLowPowerModeEnabled: Bool) {
        if isLowPowerModeEnabled {
            print("[PubkyNoise] Low power mode enabled - switching to battery optimization")
            configureBatterySaverMode()
        } else {
            print("[PubkyNoise] Low power mode disabled - using normal configuration")
            // Use default or performance config
        }
    }
    
    /**
     * Example: Adjust chunk size based on network and battery.
     *
     * Balance between performance and battery consumption.
     */
    func optimizeChunkSize(networkQuality: String, batteryLevel: Int) {
        let chunkSize: UInt64 = {
            switch (networkQuality.lowercased(), batteryLevel) {
            case ("poor", _), (_, 0..<30):
                return 16384  // Low battery or poor network: small chunks
            case ("good", 50...), ("excellent", 70...):
                return 65536  // Excellent network and good battery: large chunks
            default:
                return 32768  // Default
            }
        }()
        
        print("[PubkyNoise] Optimized chunk size: \(chunkSize) bytes (network: \(networkQuality), battery: \(batteryLevel)%)")
    }
    
    // MARK: - Thread-Safety Examples
    
    /**
     * Example: Encrypt data from a background queue.
     *
     * The FfiNoiseManager is thread-safe and can be used from any queue.
     * This example shows how to perform encryption operations on a background
     * queue using DispatchQueue.
     */
    func encryptFromBackgroundQueue(data: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        let backgroundQueue = DispatchQueue(label: "com.pubky.noise.background", qos: .userInitiated)
        
        backgroundQueue.async { [weak self] in
            guard let self = self else { return }
            
            guard let manager = self.manager else {
                DispatchQueue.main.async {
                    completion(.failure(NoiseManagerError.notInitialized))
                }
                return
            }
            
            guard let sid = self.sessionId else {
                DispatchQueue.main.async {
                    completion(.failure(NoiseManagerError.noActiveSession))
                }
                return
            }
            
            do {
                // Encrypt on background queue
                let ciphertext = try manager.encrypt(sessionId: sid, plaintext: data)
                
                // Switch back to main queue for completion
                DispatchQueue.main.async {
                    print("[PubkyNoise] Encryption completed on background queue: \(ciphertext.count) bytes")
                    completion(.success(ciphertext))
                }
                
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
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
    func performConcurrentEncryption(messages: [String]) async throws -> [Data] {
        guard let manager = manager else {
            throw NoiseManagerError.notInitialized
        }
        
        guard let sid = sessionId else {
            throw NoiseManagerError.noActiveSession
        }
        
        // Use TaskGroup for concurrent operations
        return try await withThrowingTaskGroup(of: Data?.self) { group in
            for message in messages {
                group.addTask { [weak self] in
                    guard let self = self else { return nil }
                    
                    do {
                        guard let data = message.data(using: .utf8) else {
                            return nil
                        }
                        
                        let ciphertext = try manager.encrypt(sessionId: sid, plaintext: data)
                        print("[PubkyNoise] Encrypted: \(message) -> \(ciphertext.count) bytes")
                        return ciphertext
                    } catch {
                        print("[PubkyNoise] Failed to encrypt '\(message)': \(error.localizedDescription)")
                        return nil
                    }
                }
            }
            
            // Collect results
            var results: [Data] = []
            for try await result in group {
                if let data = result {
                    results.append(data)
                }
            }
            
            print("[PubkyNoise] Concurrent encryption complete: \(results.count)/\(messages.count) succeeded")
            return results
        }
    }
    
    /**
     * Example: Thread-safe session access from multiple queues.
     *
     * This demonstrates that the manager can be safely accessed from
     * multiple queues simultaneously.
     */
    func demonstrateThreadSafeAccess() {
        guard let manager = manager, let sid = sessionId else { return }
        
        let backgroundQueue = DispatchQueue(label: "com.pubky.noise.concurrent", attributes: .concurrent)
        
        // Launch operations from multiple queues
        for threadIndex in 0..<5 {
            backgroundQueue.async { [weak self] in
                guard let self = self else { return }
                
                do {
                    let message = "Message from queue \(threadIndex)"
                    guard let data = message.data(using: .utf8) else { return }
                    
                    // All queues can safely access the manager
                    let ciphertext = try manager.encrypt(sessionId: sid, plaintext: data)
                    print("[PubkyNoise] Queue \(threadIndex): Encrypted \(data.count) bytes -> \(ciphertext.count) bytes")
                    
                } catch {
                    print("[PubkyNoise] Queue \(threadIndex) failed: \(error.localizedDescription)")
                }
            }
        }
    }
    
    /**
     * Example: Background operation with proper error handling.
     *
     * Shows best practices for using the manager from background queues
     * with proper error handling and queue switching.
     */
    func backgroundOperationWithErrorHandling(operation: @escaping () throws -> Void) {
        let backgroundQueue = DispatchQueue(label: "com.pubky.noise.background", qos: .userInitiated)
        
        backgroundQueue.async { [weak self] in
            do {
                try operation()
            } catch let error as FfiNoiseError {
                // Handle FFI errors
                DispatchQueue.main.async {
                    self?.handleError(context: "Background operation failed", error: error)
                }
            } catch {
                // Handle other errors
                DispatchQueue.main.async {
                    print("[PubkyNoise] Unexpected error in background: \(error.localizedDescription)")
                }
            }
        }
    }
    
    // MARK: - Error Handling
    
    /**
     * Comprehensive error handler for FfiNoiseError.
     *
     * Maps error types to appropriate handling strategies.
     *
     * - Parameter context: Description of what operation failed
     * - Parameter error: The FfiNoiseError to handle
     */
    private func handleError(context: String, error: FfiNoiseError) {
        switch error {
        case .ring(let message):
            // Key management error - check seed/key configuration
            print("[PubkyNoise] \(context): Key error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .keyError(message))
            
        case .invalidPeerKey:
            // Invalid server key - may indicate MITM or misconfiguration
            print("[PubkyNoise] \(context): Invalid peer key - possible security issue!")
            delegate?.noiseManager(self, didEncounterError: .securityError("Invalid peer key"))
            
        case .identityVerify:
            // Identity verification failed - signature mismatch
            print("[PubkyNoise] \(context): Identity verification failed")
            delegate?.noiseManager(self, didEncounterError: .securityError("Identity verification failed"))
            
        case .network(let message):
            // Network error - retry may help
            print("[PubkyNoise] \(context): Network error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .networkError(message))
            
        case .timeout(let message):
            // Timeout - operation took too long
            print("[PubkyNoise] \(context): Timeout - \(message)")
            delegate?.noiseManager(self, didEncounterError: .timeout(message))
            
        case .snow(let message):
            // Noise protocol error - internal error
            print("[PubkyNoise] \(context): Protocol error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .protocolError(message))
            
        case .serde(let message):
            // Serialization error - data format issue
            print("[PubkyNoise] \(context): Serialization error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .dataError(message))
            
        case .decryption(let message):
            // Decryption failed - data may be corrupted or keys out of sync
            print("[PubkyNoise] \(context): Decryption error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .decryptionError(message))
            
        case .storage(let message):
            // Storage operation failed
            print("[PubkyNoise] \(context): Storage error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .storageError(message))
            
        case .policy(let message):
            // Policy violation - rate limiting or other restrictions
            print("[PubkyNoise] \(context): Policy violation - \(message)")
            delegate?.noiseManager(self, didEncounterError: .policyError(message))
            
        case .remoteStaticMissing:
            // Server static key not available
            print("[PubkyNoise] \(context): Remote static key missing")
            delegate?.noiseManager(self, didEncounterError: .configurationError("Remote static key missing"))
            
        case .pkarr(let message):
            // PKARR-related error (if enabled)
            print("[PubkyNoise] \(context): PKARR error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .other(message))
            
        case .other(let message):
            // Unknown/other error
            print("[PubkyNoise] \(context): Other error - \(message)")
            delegate?.noiseManager(self, didEncounterError: .other(message))
        }
    }
    
    // MARK: - Helper Methods
    
    private func statusToString(_ status: FfiConnectionStatus) -> String {
        switch status {
        case .connected: return "connected"
        case .reconnecting: return "reconnecting"
        case .disconnected: return "disconnected"
        case .error: return "error"
        }
    }
    
    private func stringToStatus(_ string: String) -> FfiConnectionStatus {
        switch string {
        case "connected": return .connected
        case "reconnecting": return .reconnecting
        case "disconnected": return .disconnected
        default: return .error
        }
    }
}

// MARK: - Delegate Protocol

/**
 * Protocol for receiving NoiseManager events.
 */
protocol NoiseManagerDelegate: AnyObject {
    /// Called when a session is successfully established
    func noiseManager(_ manager: NoiseManager, didEstablishSession sessionId: String)
    
    /// Called when the connection status changes
    func noiseManager(_ manager: NoiseManager, didChangeStatus status: FfiConnectionStatus)
    
    /// Called when an error occurs
    func noiseManager(_ manager: NoiseManager, didEncounterError error: NoiseManagerError)
}

// Default implementations (optional methods)
extension NoiseManagerDelegate {
    func noiseManager(_ manager: NoiseManager, didEstablishSession sessionId: String) {}
    func noiseManager(_ manager: NoiseManager, didChangeStatus status: FfiConnectionStatus) {}
    func noiseManager(_ manager: NoiseManager, didEncounterError error: NoiseManagerError) {}
}

// MARK: - Error Types

/**
 * High-level error types for NoiseManager.
 */
enum NoiseManagerError: Error, LocalizedError {
    case notInitialized
    case noActiveSession
    case noPendingHandshake
    case invalidKeyLength
    case invalidInput
    case invalidOutput
    case invalidState
    case keyError(String)
    case securityError(String)
    case networkError(String)
    case timeout(String)
    case protocolError(String)
    case dataError(String)
    case decryptionError(String)
    case storageError(String)
    case policyError(String)
    case configurationError(String)
    case other(String)
    
    var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "Noise manager not initialized"
        case .noActiveSession:
            return "No active session"
        case .noPendingHandshake:
            return "No pending handshake to complete"
        case .invalidKeyLength:
            return "Invalid key length (expected 32 bytes)"
        case .invalidInput:
            return "Invalid input data"
        case .invalidOutput:
            return "Invalid output data"
        case .invalidState:
            return "Invalid saved state"
        case .keyError(let msg):
            return "Key error: \(msg)"
        case .securityError(let msg):
            return "Security error: \(msg)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        case .timeout(let msg):
            return "Timeout: \(msg)"
        case .protocolError(let msg):
            return "Protocol error: \(msg)"
        case .dataError(let msg):
            return "Data error: \(msg)"
        case .decryptionError(let msg):
            return "Decryption error: \(msg)"
        case .storageError(let msg):
            return "Storage error: \(msg)"
        case .policyError(let msg):
            return "Policy error: \(msg)"
        case .configurationError(let msg):
            return "Configuration error: \(msg)"
        case .other(let msg):
            return msg
        }
    }
}

// MARK: - App Lifecycle Integration

/**
 * Extension for integrating with iOS app lifecycle.
 *
 * Add these notifications in your AppDelegate or SceneDelegate:
 *
 * ```swift
 * NotificationCenter.default.addObserver(
 *     noiseManager,
 *     selector: #selector(NoiseManager.applicationWillResignActive),
 *     name: UIApplication.willResignActiveNotification,
 *     object: nil
 * )
 *
 * NotificationCenter.default.addObserver(
 *     noiseManager,
 *     selector: #selector(NoiseManager.applicationDidBecomeActive),
 *     name: UIApplication.didBecomeActiveNotification,
 *     object: nil
 * )
 * ```
 */
extension NoiseManager {
    
    /**
     * Called when app is about to become inactive.
     * Saves session state for later restoration.
     */
    @objc func applicationWillResignActive() {
        print("[PubkyNoise] App resigning active - saving state")
        saveState()
    }
    
    /**
     * Called when app becomes active.
     * Checks and updates connection status.
     */
    @objc func applicationDidBecomeActive() {
        print("[PubkyNoise] App became active")
        
        // Check current status
        if let status = getConnectionStatus() {
            print("[PubkyNoise] Current status: \(status)")
            
            // If disconnected, you might want to reconnect
            if status == .disconnected || status == .error {
                setConnectionStatus(.reconnecting)
                // TODO: Implement reconnection logic
            }
        }
    }
}

// MARK: - Usage Example

/**
 * Example usage of NoiseManager.
 *
 * ```swift
 * class MyViewController: UIViewController, NoiseManagerDelegate {
 *     let noiseManager = NoiseManager()
 *
 *     override func viewDidLoad() {
 *         super.viewDidLoad()
 *         noiseManager.delegate = self
 *
 *         // Start connection
 *         connectToServer()
 *     }
 *
 *     func connectToServer() {
 *         let serverKey = Data([...])  // 32 bytes
 *
 *         do {
 *             // Step 1: Initiate
 *             let firstMessage = try noiseManager.initiateConnection(serverPublicKey: serverKey)
 *
 *             // Step 2: Send to server (your network code)
 *             sendToServer(firstMessage) { response in
 *                 do {
 *                     // Step 3: Complete
 *                     try self.noiseManager.completeConnection(serverResponse: response)
 *                 } catch {
 *                     print("Connection failed: \(error)")
 *                 }
 *             }
 *         } catch {
 *             print("Failed to initiate: \(error)")
 *         }
 *     }
 *
 *     func sendMessage(_ text: String) {
 *         do {
 *             let ciphertext = try noiseManager.encrypt(message: text)
 *             // Send ciphertext over network
 *         } catch {
 *             print("Encryption failed: \(error)")
 *         }
 *     }
 *
 *     // MARK: - NoiseManagerDelegate
 *
 *     func noiseManager(_ manager: NoiseManager, didEstablishSession sessionId: String) {
 *         print("Connected! Session: \(sessionId)")
 *     }
 *
 *     func noiseManager(_ manager: NoiseManager, didEncounterError error: NoiseManagerError) {
 *         print("Error: \(error.localizedDescription)")
 *     }
 * }
 * ```
 */
#if DEBUG
class NoiseManagerUsageExample {
    func demonstrateUsage() {
        let manager = NoiseManager()
        
        // Example server public key (replace with real key)
        let serverKey = Data(repeating: 0x02, count: 32)
        
        do {
            // Step 1: Initiate connection
            let firstMessage = try manager.initiateConnection(serverPublicKey: serverKey)
            print("First message ready to send: \(firstMessage.count) bytes")
            
            // Step 2: In real app, send firstMessage to server and get response
            // let response = network.send(firstMessage)
            
            // Step 3: Complete connection (with mock response for demo)
            // try manager.completeConnection(serverResponse: response)
            
            // After connection established:
            // let ciphertext = try manager.encrypt(message: "Hello, server!")
            // let plaintext = try manager.decrypt(ciphertext: receivedData)
            
        } catch {
            print("Error: \(error)")
        }
    }
}
#endif
