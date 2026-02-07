//! Production-ready Noise Protocol implementation for Pubky.
//!
//! This crate provides authenticated, encrypted communication channels using the
//! Noise Protocol Framework. It supports both XX (trust-on-first-use) and IK
//! (known server) handshake patterns.
//!
//! ## Quick Start
//!
//! ```rust
//! use pubky_noise::{NoiseClient, NoiseServer, DummyRing};
//! use std::sync::Arc;
//!
//! // Setup client and server with key providers
//! let client_ring = Arc::new(DummyRing::new([1u8; 32], "client_kid"));
//! let server_ring = Arc::new(DummyRing::new([2u8; 32], "server_kid"));
//!
//! let client = NoiseClient::<_, ()>::new_direct("client_kid", b"client_device", client_ring);
//! let server = NoiseServer::<_, ()>::new_direct("server_kid", b"server_device", server_ring);
//! ```

#![allow(unpredictable_function_pointer_comparisons)]

pub mod client;
pub mod datalink_adapter;
pub mod errors;
#[cfg(feature = "uniffi_macros")]
pub mod ffi;
#[cfg(feature = "storage-queue")]
pub mod handshake_queue;
pub mod identity_payload;
// Re-export pubky-crypto modules (backward-compatible)
pub use pubky_crypto::kdf;
pub mod mobile_manager;
#[cfg(feature = "pkarr")]
pub mod pkarr;
pub mod prelude;
#[cfg(feature = "pubky-sdk")]
pub mod pubky_ring;
pub mod rate_limiter;
pub mod ring;
#[cfg(feature = "secure-mem")]
pub use pubky_crypto::secure_mem;
pub use pubky_crypto::sealed_blob;
pub use pubky_crypto::sealed_blob_v2;
pub mod server;
pub use pubky_crypto::ukd;
pub mod session_id;
pub mod session_manager;
#[cfg(feature = "storage-queue")]
pub mod storage_queue;
pub mod streaming;
pub mod transport;

pub use client::NoiseClient;
pub use datalink_adapter::NoiseLink;
pub use errors::{NoiseError, NoiseErrorCode, NoiseResult};
#[cfg(feature = "storage-queue")]
pub use handshake_queue::HandshakeQueue;
pub use identity_payload::BindingMessageParams;
pub use pubky_crypto::{ed25519_sign, ed25519_verify};
pub use mobile_manager::{ConnectionStatus, MobileConfig, NoiseManager, SessionState};
#[cfg(feature = "pkarr")]
pub use pkarr::{DummyPkarr, PkarrNoiseRecord, PkarrResolver};
#[cfg(feature = "pubky-sdk")]
pub use pubky_ring::PubkyRingProvider;
pub use rate_limiter::{RateLimitReason, RateLimitResult, RateLimiter, RateLimiterConfig};
pub use ring::{DummyRing, RingKeyFiller, RingKeyProvider};
pub use pubky_crypto::sealed_blob::{
    is_sealed_blob, sealed_blob_decrypt, sealed_blob_encrypt, x25519_generate_keypair,
    x25519_public_from_secret, SealedBlobEnvelope, MAX_PLAINTEXT_SIZE, SEALED_BLOB_VERSION,
    NONCE_SIZE_V2,
};
pub use pubky_crypto::sealed_blob_v2::{
    Sb2, Sb2Header, build_aad as sb2_build_aad, compute_sig_input as sb2_compute_sig_input,
    SB2_MAGIC, SB2_VERSION, MAX_HEADER_LEN, MAX_MSG_ID_LEN, AAD_PREFIX as SB2_AAD_PREFIX,
};
pub use pubky_crypto::ukd::{
    derive_cert_id, generate_app_keypair, issue_app_cert, sign_typed_content,
    verify_app_cert, verify_typed_content, AppCert, AppCertInput, CERT_ID_LEN,
    KeyBinding, InboxKeyEntry, TransportKeyEntry, AppKeyEntry,
};
pub use server::{NoiseServer, ServerPolicy};
pub use session_id::SessionId;
pub use session_manager::{NoiseRole, NoiseSessionManager, ThreadSafeSessionManager};
#[cfg(feature = "storage-queue")]
pub use storage_queue::{MessageQueue, RetryConfig, StorageBackedMessaging};
pub use streaming::StreamingNoiseLink;
pub use transport::NoiseTransport;

// UniFFI setup - must be at crate root for proc macros to work
#[cfg(feature = "uniffi_macros")]
uniffi::setup_scaffolding!();
