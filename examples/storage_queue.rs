//! Storage-Backed Messaging Example
//!
//! This example demonstrates storage-backed messaging using the Pubky storage
//! system. This feature requires the `storage-queue` feature to be enabled
//! and a Pubky session with storage access.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example storage_queue --features storage-queue
//! ```
//!
//! **Note**: This example requires the `storage-queue` feature and Pubky
//! infrastructure. It demonstrates the API and configuration patterns even
//! if you don't have a full Pubky setup.
//!
//! ## Overview
//!
//! Storage-backed messaging allows you to send encrypted messages through
//! Pubky's distributed storage system. Messages are encrypted using Noise
//! and stored in the sender's repository, where the receiver can poll for them.
//!
//! **Critical**: You must persist `write_counter` and `read_counter` values
//! across application restarts to avoid data loss or message replay.

#![cfg(feature = "storage-queue")]

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
// These imports are used in the code comments/examples - keep for documentation
#[allow(unused_imports)]
use pubky_noise::storage_queue::{MessageQueue, RetryConfig, StorageBackedMessaging};
use pubky_noise::{DummyRing, NoiseClient, NoiseServer, RingKeyProvider};
use std::sync::Arc;

// Note: This example demonstrates the API structure but requires actual
// PubkySession and PublicStorage instances to run. In production, you would
// obtain these from your Pubky setup.

fn main() {
    println!("=== PubkyNoise Storage-Backed Messaging Example ===\n");

    // =========================================================================
    // Setup
    // =========================================================================

    println!("1. Setting up client and server...");

    let ring_client = Arc::new(DummyRing::new([1u8; 32], "client"));
    let ring_server = Arc::new(DummyRing::new([2u8; 32], "server"));

    let client = NoiseClient::<_, ()>::new_direct("client", b"device", ring_client);
    let server = NoiseServer::<_, ()>::new_direct("server", b"device", ring_server.clone());

    let server_sk = ring_server
        .derive_device_x25519("server", b"device", 0)
        .unwrap();
    let server_pk = pubky_noise::kdf::x25519_pk_from_sk(&server_sk);

    // Complete handshake
    let (c_hs, first_msg) = client_start_ik_direct(&client, &server_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let _s_link = server_complete_ik(s_hs).unwrap();

    println!("   Handshake complete");
    println!("   Session ID: {}", c_link.session_id());

    // =========================================================================
    // Retry Configuration
    // =========================================================================

    println!("\n2. Configuring retry behavior...");

    // Default retry configuration
    let default_config = RetryConfig::default();
    println!("   Default config:");
    println!("     max_retries: {}", default_config.max_retries);
    println!(
        "     initial_backoff_ms: {}",
        default_config.initial_backoff_ms
    );
    println!("     max_backoff_ms: {}", default_config.max_backoff_ms);
    println!(
        "     operation_timeout_ms: {}",
        default_config.operation_timeout_ms
    );

    // Custom retry configuration for different scenarios
    let aggressive_config = RetryConfig {
        max_retries: 10,
        initial_backoff_ms: 50,
        max_backoff_ms: 2000,
        operation_timeout_ms: 5000,
    };

    let conservative_config = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 500,
        max_backoff_ms: 10000,
        operation_timeout_ms: 60000,
    };

    println!("\n   Aggressive config (quick retries):");
    println!("     max_retries: {}", aggressive_config.max_retries);
    println!(
        "     initial_backoff_ms: {}",
        aggressive_config.initial_backoff_ms
    );

    println!("\n   Conservative config (patient retries):");
    println!("     max_retries: {}", conservative_config.max_retries);
    println!(
        "     initial_backoff_ms: {}",
        conservative_config.initial_backoff_ms
    );

    // =========================================================================
    // Storage-Backed Messaging Setup
    // =========================================================================

    println!("\n3. Storage-backed messaging setup...");

    println!("   To create StorageBackedMessaging, you need:");
    println!("   - A NoiseLink (from handshake)");
    println!("   - A PubkySession (for authenticated writes)");
    println!("   - A PublicStorage client (for public reads)");
    println!("   - Write path (your repository path)");
    println!("   - Read path (peer's repository path)");

    // Example setup (would require actual Pubky infrastructure):
    /*
    let mut messaging = StorageBackedMessaging::new(
        c_link,
        pubky_session,      // From your Pubky setup
        public_storage,     // From your Pubky setup
        "/my/repo/messages".to_string(),
        "/peer/repo/messages".to_string(),
    )
    .with_retry_config(aggressive_config)
    .with_counters(0, 0);  // Start with zero counters
    */

    println!("\n   Example code structure:");
    println!("   ```rust");
    println!("   let mut messaging = StorageBackedMessaging::new(");
    println!("       noise_link,");
    println!("       pubky_session,");
    println!("       public_storage,");
    println!("       write_path,");
    println!("       read_path,");
    println!("   ).with_retry_config(config)");
    println!("    .with_counters(saved_write_counter, saved_read_counter);");
    println!("   ```");

    // =========================================================================
    // Counter Persistence (CRITICAL)
    // =========================================================================

    println!("\n4. Counter persistence (CRITICAL for production)...");

    println!("   ⚠️  IMPORTANT: You MUST persist counters across app restarts!");
    println!("\n   Why:");
    println!("   - write_counter: Prevents message loss on sender side");
    println!("   - read_counter: Prevents message replay on receiver side");
    println!("\n   How to persist:");
    println!("   1. Save counters after each send/receive operation");
    println!("   2. Restore counters when creating StorageBackedMessaging");
    println!("   3. Use with_counters() to set initial values");

    println!("\n   Example persistence pattern:");
    println!("   ```rust");
    println!("   // After sending a message");
    println!("   let write_counter = messaging.write_counter();");
    println!("   save_to_disk(write_counter);");
    println!("\n   // On app restart");
    println!("   let saved_counter = load_from_disk();");
    println!("   let messaging = StorageBackedMessaging::new(...)");
    println!("       .with_counters(saved_counter, 0);");
    println!("   ```");

    // =========================================================================
    // Sending Messages
    // =========================================================================

    println!("\n5. Sending messages...");

    println!("   Storage-backed messaging uses async operations:");
    println!("   ```rust");
    println!("   // Send a message");
    println!("   messaging.send_message(b\"Hello, world!\").await?;");
    println!("\n   // Get updated counter for persistence");
    println!("   let counter = messaging.write_counter();");
    println!("   persist_counter(counter);");
    println!("   ```");

    println!("\n   Features:");
    println!("   - Automatic retry with exponential backoff");
    println!("   - Encrypted using Noise protocol");
    println!("   - Stored in sender's repository");
    println!("   - Counter incremented automatically");

    // =========================================================================
    // Receiving Messages
    // =========================================================================

    println!("\n6. Receiving messages...");

    println!("   ```rust");
    println!("   // Receive messages (polls peer's repository)");
    println!("   let messages = messaging.receive_messages(Some(10)).await?;");
    println!("\n   // Process each message");
    println!("   for message in messages {{");
    println!("       println!(\"Received: {{:?}}\", message);");
    println!("   }}");
    println!("\n   // Get updated counter for persistence");
    println!("   let counter = messaging.read_counter();");
    println!("   persist_counter(counter);");
    println!("   ```");

    println!("\n   Features:");
    println!("   - Polls peer's repository for new messages");
    println!("   - Automatically decrypts using Noise");
    println!("   - Handles transient network errors");
    println!("   - Counter incremented automatically");

    // =========================================================================
    // MessageQueue Trait
    // =========================================================================

    println!("\n7. Using the MessageQueue trait...");

    println!("   StorageBackedMessaging implements MessageQueue:");
    println!("   ```rust");
    println!("   // Enqueue a message");
    println!("   messaging.enqueue(b\"Hello\").await?;");
    println!("\n   // Dequeue messages");
    println!("   while let Some(message) = messaging.dequeue().await? {{");
    println!("       process_message(message);");
    println!("   }}");
    println!("   ```");

    // =========================================================================
    // Error Handling
    // =========================================================================

    println!("\n8. Error handling...");

    println!("   Common errors:");
    println!("   - NoiseError::Storage: Storage operation failed");
    println!("   - NoiseError::Network: Network connectivity issue");
    println!("   - NoiseError::Timeout: Operation timed out");

    println!("\n   Error handling pattern:");
    println!("   ```rust");
    println!("   match messaging.send_message(data).await {{");
    println!("       Ok(_) => println!(\"Message sent\"),");
    println!("       Err(NoiseError::Storage(msg)) => {{");
    println!("           // Retry or handle storage error");
    println!("       }}");
    println!("       Err(e) => handle_error(e),");
    println!("   }}");
    println!("   ```");

    // =========================================================================
    // Best Practices
    // =========================================================================

    println!("\n9. Best practices...");

    println!("   ✅ DO:");
    println!("   - Always persist write_counter and read_counter");
    println!("   - Use appropriate retry config for your use case");
    println!("   - Handle storage errors gracefully");
    println!("   - Monitor counter values for anomalies");

    println!("\n   ❌ DON'T:");
    println!("   - Reset counters without good reason");
    println!("   - Ignore storage errors");
    println!("   - Use zero retries in production");
    println!("   - Share counters between multiple instances");

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Storage-Backed Messaging Example Complete! ===");
    println!("\nKey points:");
    println!("- Requires 'storage-queue' feature and Pubky infrastructure");
    println!("- Messages are encrypted and stored in Pubky repositories");
    println!("- CRITICAL: Persist counters across app restarts");
    println!("- Configure retry behavior based on network conditions");
    println!("- Use async/await for all messaging operations");
    println!("\nNext steps:");
    println!("1. Set up Pubky session and storage");
    println!("2. Create StorageBackedMessaging with proper paths");
    println!("3. Implement counter persistence");
    println!("4. Handle errors and retries appropriately");
}
