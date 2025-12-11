//! Streaming / Large Message Example
//!
//! This example demonstrates how to handle large messages using
//! the StreamingNoiseLink wrapper.
//!
//! ## Running
//!
//! ```bash
//! cargo run --example streaming
//! ```
//!
//! ## Overview
//!
//! The Noise protocol has a per-message size limit (around 65535 bytes).
//! StreamingNoiseLink automatically splits large messages into chunks
//! and reassembles them on the other side.

use pubky_noise::datalink_adapter::{
    client_complete_ik, client_start_ik_direct, server_accept_ik, server_complete_ik,
};
use pubky_noise::{DummyRing, NoiseClient, NoiseServer, RingKeyProvider, StreamingNoiseLink};
use std::sync::Arc;

fn main() {
    println!("=== PubkyNoise Streaming Example ===\n");

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
    let s_link = server_complete_ik(s_hs).unwrap();

    println!("   Handshake complete");

    // =========================================================================
    // Streaming with Custom Chunk Size
    // =========================================================================

    println!("\n2. Testing with small chunk size (for demonstration)...");

    // Use small chunk size to see chunking in action
    let chunk_size = 50;
    let mut c_stream = StreamingNoiseLink::new(c_link, chunk_size);
    let mut s_stream = StreamingNoiseLink::new(s_link, chunk_size);

    // Create a message larger than chunk size
    let message = b"This is a longer message that will be split into multiple chunks for transmission over the noise protocol. Each chunk is encrypted separately.";

    println!("   Original message: {} bytes", message.len());
    println!("   Chunk size: {} bytes", chunk_size);

    // Encrypt - automatically splits into chunks
    let chunks = c_stream
        .encrypt_streaming(message)
        .expect("Streaming encrypt failed");

    println!("   Split into {} chunks:", chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        println!("     Chunk {}: {} bytes", i + 1, chunk.len());
    }

    // Decrypt - automatically reassembles
    let decrypted = s_stream
        .decrypt_streaming(&chunks)
        .expect("Streaming decrypt failed");

    assert_eq!(message.to_vec(), decrypted);
    println!("   Decrypted and reassembled: {} bytes", decrypted.len());
    println!(
        "   Content: {:?}",
        String::from_utf8_lossy(&decrypted[..50])
    );

    // =========================================================================
    // Default Chunk Size (Mobile-Friendly)
    // =========================================================================

    println!("\n3. Testing with default chunk size (65536 bytes)...");

    // Reset for new streaming links
    let ring_client2 = Arc::new(DummyRing::new([3u8; 32], "client2"));
    let ring_server2 = Arc::new(DummyRing::new([4u8; 32], "server2"));

    let client2 = NoiseClient::<_, ()>::new_direct("client2", b"device", ring_client2);
    let server2 = NoiseServer::<_, ()>::new_direct("server2", b"device", ring_server2.clone());

    let server2_sk = ring_server2
        .derive_device_x25519("server2", b"device", 0)
        .unwrap();
    let server2_pk = pubky_noise::kdf::x25519_pk_from_sk(&server2_sk);

    let (c_hs, first_msg) = client_start_ik_direct(&client2, &server2_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server2, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    // Use default chunk size
    let mut c_stream = StreamingNoiseLink::new_with_default_chunk_size(c_link);
    let mut s_stream = StreamingNoiseLink::new_with_default_chunk_size(s_link);

    // Create a large message (100KB)
    let large_message: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    println!("   Large message: {} bytes (100KB)", large_message.len());

    let chunks = c_stream
        .encrypt_streaming(&large_message)
        .expect("Encrypt failed");

    println!("   Split into {} chunks", chunks.len());

    let decrypted = s_stream.decrypt_streaming(&chunks).expect("Decrypt failed");

    assert_eq!(large_message, decrypted);
    println!("   Decrypted successfully: {} bytes", decrypted.len());

    // =========================================================================
    // Individual Chunk Operations
    // =========================================================================

    println!("\n4. Individual chunk operations...");

    let ring_client3 = Arc::new(DummyRing::new([5u8; 32], "client3"));
    let ring_server3 = Arc::new(DummyRing::new([6u8; 32], "server3"));

    let client3 = NoiseClient::<_, ()>::new_direct("client3", b"device", ring_client3);
    let server3 = NoiseServer::<_, ()>::new_direct("server3", b"device", ring_server3.clone());

    let server3_sk = ring_server3
        .derive_device_x25519("server3", b"device", 0)
        .unwrap();
    let server3_pk = pubky_noise::kdf::x25519_pk_from_sk(&server3_sk);

    let (c_hs, first_msg) = client_start_ik_direct(&client3, &server3_pk, None).unwrap();
    let (s_hs, _, response) = server_accept_ik(&server3, &first_msg).unwrap();
    let c_link = client_complete_ik(c_hs, &response).unwrap();
    let s_link = server_complete_ik(s_hs).unwrap();

    let mut c_stream = StreamingNoiseLink::new(c_link, 1000);
    let mut s_stream = StreamingNoiseLink::new(s_link, 1000);

    // Encrypt individual chunks (useful for progress tracking)
    let data = b"Short message";
    let encrypted_chunk = c_stream.encrypt_chunk(data).expect("Chunk encrypt failed");
    println!(
        "   Single chunk: {} -> {} bytes",
        data.len(),
        encrypted_chunk.len()
    );

    let decrypted_chunk = s_stream
        .decrypt_chunk(&encrypted_chunk)
        .expect("Chunk decrypt failed");
    println!(
        "   Decrypted: {:?}",
        String::from_utf8_lossy(&decrypted_chunk)
    );

    // Accessing the underlying NoiseLink
    let _session_id = c_stream.inner().session_id();
    println!("   Session ID from streaming link: {}", _session_id);

    // =========================================================================
    // Mobile-Friendly Chunk Sizes
    // =========================================================================

    println!("\n5. Recommended chunk sizes for mobile...");

    println!("   16KB  - Battery saver / poor network");
    println!("   32KB  - Default mobile (balanced)");
    println!("   64KB  - Good network / performance mode");

    // Example of mobile-friendly configuration
    let mobile_chunk_sizes = [
        (16 * 1024, "Battery saver"),
        (32 * 1024, "Default mobile"),
        (64 * 1024, "Performance mode"),
    ];

    for (size, mode) in mobile_chunk_sizes {
        println!(
            "   {} ({} bytes): Good for {}",
            mode,
            size,
            mode.to_lowercase()
        );
    }

    // =========================================================================
    // Summary
    // =========================================================================

    println!("\n=== Streaming example complete! ===");
    println!("\nKey points:");
    println!("- StreamingNoiseLink handles chunking automatically");
    println!("- Choose chunk size based on network conditions");
    println!("- Smaller chunks = more overhead, better for poor networks");
    println!("- Larger chunks = less overhead, better for good networks");
    println!("- Default chunk size (64KB) works well for most cases");
}
