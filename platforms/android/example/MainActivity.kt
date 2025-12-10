package com.pubky.noise.example

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.pubky.noise.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    private var manager: FfiNoiseManager? = null
    private var sessionId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        setupNoise()
        connect()
    }

    private fun setupNoise() {
        try {
            // 1. Configure
            val config = FfiMobileConfig(
                autoReconnect = true,
                maxReconnectAttempts = 5u,
                reconnectDelayMs = 1000u,
                batterySaver = false,
                chunkSize = 32768u
            )

            // 2. Create Manager
            val clientSeed = ByteArray(32) // Replace with real seed
            val deviceId = "device-123".toByteArray()

            manager = FfiNoiseManager(
                config,
                clientSeed,
                "my-key-id",
                deviceId
            )
            println("Manager created")
            
        } catch (e: Exception) {
            println("Failed to create manager: ${e.message}")
        }
    }

    private fun connect() {
        val mgr = manager ?: return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val serverPk = ByteArray(32) // Replace with server static PK
                val sid = mgr.connectClient(serverPk, 0u, null)
                
                withContext(Dispatchers.Main) {
                    sessionId = sid
                    println("Connected! Session ID: $sid")
                }
            } catch (e: Exception) {
                println("Connection failed: ${e.message}")
            }
        }
    }
}

