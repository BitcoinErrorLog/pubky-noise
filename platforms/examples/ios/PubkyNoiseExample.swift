// PubkyNoiseExample.swift
// Example usage of pubky-noise in iOS/Swift
// Version: 0.8.0

import Foundation
import PubkyNoise

/// Example: Cold Key Setup and Connection
///
/// This demonstrates the recommended pattern for Bitkit integration:
/// 1. Derive X25519 key from Ed25519 identity (one-time, cold operation)
/// 2. Use FfiRawNoiseManager for connections
/// 3. Select appropriate pattern based on use case
class PubkyNoiseExample {
    
    private var manager: FfiRawNoiseManager?
    
    // MARK: - Initialization
    
    /// Create a new noise manager with default mobile configuration
    func initialize() {
        let config = FfiMobileConfig(
            autoReconnect: true,
            maxReconnectAttempts: 3,
            reconnectDelayMs: 1000,
            batterySaver: true,
            chunkSize: 65535
        )
        
        manager = FfiRawNoiseManager(config: config)
        print("PubkyNoise manager initialized")
    }
    
    // MARK: - Key Derivation
    
    /// Derive X25519 session key from Ed25519 identity seed
    ///
    /// Call this once during device setup. The Ed25519 key can then be stored cold.
    ///
    /// - Parameters:
    ///   - ed25519Seed: 32-byte Ed25519 secret key seed
    ///   - deviceId: Device identifier for derivation context
    /// - Returns: Tuple of (X25519 secret key, X25519 public key)
    func deriveNoiseKeypair(ed25519Seed: Data, deviceId: String) throws -> (secretKey: Data, publicKey: Data) {
        let context = deviceId.data(using: .utf8)!
        
        // Derive X25519 secret key
        let secretKey = try ffiDeriveX25519Static(
            seed: Array(ed25519Seed),
            context: Array(context)
        )
        
        // Compute public key
        let publicKey = try ffiX25519PublicKey(secretKey: secretKey)
        
        return (Data(secretKey), Data(publicKey))
    }
    
    // MARK: - Connection Patterns
    
    /// Connect using IK-raw pattern (cold key scenario)
    ///
    /// Use when:
    /// - You have pre-shared the recipient's X25519 key (via pkarr)
    /// - Your Ed25519 identity is kept cold
    /// - You want identity hiding from passive observers
    ///
    /// - Parameters:
    ///   - localSecretKey: Your X25519 secret key (32 bytes)
    ///   - serverPublicKey: Recipient's X25519 public key (32 bytes)
    /// - Returns: Session ID and first handshake message
    func connectIKRaw(localSecretKey: Data, serverPublicKey: Data) throws -> (sessionId: String, message: Data) {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let result = try manager.initiateIkRaw(
            localSk: Array(localSecretKey),
            serverPk: Array(serverPublicKey)
        )
        
        return (result.sessionId, Data(result.message))
    }
    
    /// Connect anonymously using N pattern
    ///
    /// Use when:
    /// - The sender wants to remain anonymous
    /// - The recipient is authenticated by their static key
    /// - You don't need mutual authentication
    ///
    /// - Parameters:
    ///   - serverPublicKey: Recipient's X25519 public key (32 bytes)
    /// - Returns: Session ID and first handshake message
    func connectAnonymous(serverPublicKey: Data) throws -> (sessionId: String, message: Data) {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let result = try manager.initiateAnonymous(serverPk: Array(serverPublicKey))
        
        return (result.sessionId, Data(result.message))
    }
    
    /// Connect ephemerally using NN pattern
    ///
    /// Use when:
    /// - Both parties want to remain anonymous
    /// - You have an out-of-band authentication mechanism
    /// - Maximum forward secrecy is required
    ///
    /// - Returns: Session ID and first handshake message
    func connectEphemeral() throws -> (sessionId: String, message: Data) {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let result = try manager.initiateEphemeral()
        
        return (result.sessionId, Data(result.message))
    }
    
    // MARK: - Server-Side Accept
    
    /// Accept an IK-raw connection
    func acceptIKRaw(localSecretKey: Data, firstMessage: Data) throws -> (sessionId: String, response: Data, clientKey: Data?) {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let result = try manager.acceptIkRaw(
            localSk: Array(localSecretKey),
            firstMsg: Array(firstMessage)
        )
        
        return (
            result.sessionId,
            Data(result.response),
            result.clientStaticPk.map { Data($0) }
        )
    }
    
    /// Accept an anonymous (N pattern) connection
    func acceptAnonymous(localSecretKey: Data, firstMessage: Data) throws -> (sessionId: String, response: Data) {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let result = try manager.acceptAnonymous(
            localSk: Array(localSecretKey),
            firstMsg: Array(firstMessage)
        )
        
        return (result.sessionId, Data(result.response))
    }
    
    // MARK: - Encryption/Decryption
    
    /// Encrypt a message for the given session
    func encrypt(sessionId: String, plaintext: Data) throws -> Data {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let ciphertext = try manager.encrypt(sessionId: sessionId, plaintext: Array(plaintext))
        return Data(ciphertext)
    }
    
    /// Decrypt a message for the given session
    func decrypt(sessionId: String, ciphertext: Data) throws -> Data {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        let plaintext = try manager.decrypt(sessionId: sessionId, ciphertext: Array(ciphertext))
        return Data(plaintext)
    }
    
    // MARK: - Session Management
    
    /// Save session state for persistence (e.g., app backgrounding)
    func saveSession(sessionId: String) throws -> FfiSessionState {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        return try manager.saveState(sessionId: sessionId)
    }
    
    /// Restore a saved session
    func restoreSession(state: FfiSessionState) throws {
        guard let manager = manager else {
            throw NSError(domain: "PubkyNoise", code: 1, userInfo: [NSLocalizedDescriptionKey: "Manager not initialized"])
        }
        
        try manager.restoreState(state: state)
    }
    
    /// List all active sessions
    func listSessions() -> [String] {
        return manager?.listSessions() ?? []
    }
    
    /// Remove a session
    func removeSession(sessionId: String) {
        manager?.removeSession(sessionId: sessionId)
    }
}

// MARK: - Usage Example

/*
 
 // Example: Cold key payment flow
 
 let noise = PubkyNoiseExample()
 noise.initialize()
 
 // One-time setup (cold key derivation)
 let ed25519Seed = Data(repeating: 0x01, count: 32) // Your Ed25519 secret
 let deviceId = "bitkit-ios-1"
 let (x25519Sk, x25519Pk) = try noise.deriveNoiseKeypair(ed25519Seed: ed25519Seed, deviceId: deviceId)
 
 // Store x25519Sk securely in Keychain
 // Publish x25519Pk to pkarr
 // Ed25519 key can now be stored cold
 
 // Later: Connect to recipient
 let recipientPk = Data(repeating: 0x02, count: 32) // From pkarr lookup
 let (sessionId, firstMsg) = try noise.connectIKRaw(localSecretKey: x25519Sk, serverPublicKey: recipientPk)
 
 // Send firstMsg over network...
 // Receive response...
 // Complete handshake...
 
 // Encrypt messages
 let ciphertext = try noise.encrypt(sessionId: sessionId, plaintext: "Hello".data(using: .utf8)!)
 
 */

