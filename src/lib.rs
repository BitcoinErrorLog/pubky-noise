//! Production-ready Noise Protocol implementation for Pubky.
//!
//! This crate provides authenticated, encrypted communication channels using the
//! Noise Protocol Framework. It supports both XX (trust-on-first-use) and IK
//! (known server) handshake patterns.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use pubky_noise::{NoiseClient, NoiseServer, DummyRing};
//! use pubky_noise::datalink_adapter::{client_start_ik_direct, server_accept_ik, client_complete_ik, server_complete_ik};
//! use std::sync::Arc;
//!
//! // Setup client and server with key providers
//! let client_ring = Arc::new(DummyRing::new([1u8; 32], "client_kid"));
//! let server_ring = Arc::new(DummyRing::new([2u8; 32], "server_kid"));
//!
//! let client = NoiseClient::<_, ()>::new_direct("client_kid", b"client_device", client_ring);
//! let server = NoiseServer::<_, ()>::new_direct("server_kid", b"server_device", server_ring);
//! ```

pub mod client;
pub mod datalink_adapter;
pub mod errors;
#[cfg(feature = "uniffi_macros")]
pub mod ffi;
pub mod identity_payload;
pub mod kdf;
pub mod mobile_manager;
#[cfg(feature = "pkarr")]
pub mod pkarr;
#[cfg(feature = "pubky-sdk")]
pub mod pubky_ring;
pub mod ring;
pub mod server;
pub mod session_id;
pub mod session_manager;
#[cfg(feature = "storage-queue")]
pub mod storage_queue;
pub mod streaming;
pub mod transport;

pub use client::NoiseClient;
pub use datalink_adapter::NoiseLink;
pub use errors::{NoiseError, NoiseErrorCode};
pub use identity_payload::BindingMessageParams;
pub use mobile_manager::{ConnectionStatus, MobileConfig, NoiseManager, SessionState};
#[cfg(feature = "pkarr")]
pub use pkarr::{DummyPkarr, PkarrNoiseRecord, PkarrResolver};
#[cfg(feature = "pubky-sdk")]
pub use pubky_ring::PubkyRingProvider;
pub use ring::{DummyRing, RingKeyFiller, RingKeyProvider};
pub use server::NoiseServer;
pub use session_id::SessionId;
pub use session_manager::{NoiseRole, NoiseSessionManager, ThreadSafeSessionManager};
#[cfg(feature = "storage-queue")]
pub use storage_queue::{MessageQueue, RetryConfig, StorageBackedMessaging};
pub use streaming::StreamingNoiseLink;
pub use transport::NoiseTransport;

// UniFFI setup - must be at crate root for proc macros to work
#[cfg(feature = "uniffi_macros")]
#[allow(clippy::fn_address_comparisons)]
uniffi::setup_scaffolding!();
