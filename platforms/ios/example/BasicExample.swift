import Foundation
import PubkyNoise

class NoiseExample {
    private var manager: FfiNoiseManager?
    private var sessionId: String?
    
    func setup() {
        // 1. Configure
        let config = FfiMobileConfig(
            autoReconnect: true,
            maxReconnectAttempts: 5,
            reconnectDelayMs: 1000,
            batterySaver: false,
            chunkSize: 32768
        )
        
        // 2. Create Manager
        let clientSeed = Data(count: 32) // Replace with real seed
        let deviceId = "device-123".data(using: .utf8)!
        
        do {
            manager = try FfiNoiseManager(
                config: config,
                clientSeed: clientSeed,
                clientKid: "my-key-id",
                deviceId: deviceId
            )
            print("Manager created")
        } catch {
            print("Failed to create manager: \(error)")
        }
    }
    
    func connect() {
        guard let manager = manager else { return }
        
        // Run on background queue
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let serverPk = Data(count: 32) // Replace with server static PK
                let sessionId = try manager.connectClient(
                    serverPk: serverPk,
                    epoch: 0,
                    hint: nil
                )
                
                DispatchQueue.main.async {
                    self.sessionId = sessionId
                    print("Connected! Session ID: \(sessionId)")
                }
            } catch {
                print("Connection failed: \(error)")
            }
        }
    }
    
    func encryptMessage(_ message: String) {
        guard let manager = manager, let sessionId = sessionId else { return }
        
        let data = message.data(using: .utf8)!
        
        do {
            let ciphertext = try manager.encrypt(sessionId: sessionId, plaintext: data)
            print("Encrypted \(data.count) bytes to \(ciphertext.count) bytes")
        } catch {
            print("Encryption failed: \(error)")
        }
    }
}

