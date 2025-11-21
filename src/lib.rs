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
uniffi::setup_scaffolding!();
