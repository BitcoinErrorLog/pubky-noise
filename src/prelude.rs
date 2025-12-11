//! Prelude module for convenient imports.
//!
//! This module re-exports the most commonly used types and traits for
//! quick setup. Import everything with:
//!
//! ```rust,ignore
//! use pubky_noise::prelude::*;
//! ```
//!
//! ## What's Included
//!
//! - Core types: `NoiseClient`, `NoiseServer`, `NoiseLink`, `NoiseTransport`
//! - Error types: `NoiseError`, `NoiseErrorCode`
//! - Key providers: `RingKeyProvider`, `DummyRing`
//! - Session management: `NoiseSessionManager`, `SessionId`, `NoiseRole`
//! - Configuration: `MobileConfig`, `ServerPolicy`, `RateLimiterConfig`
//! - Connection status: `ConnectionStatus`, `SessionState`

// Core client/server
pub use crate::client::NoiseClient;
pub use crate::server::{NoiseServer, ServerPolicy};

// Transport and links
pub use crate::datalink_adapter::NoiseLink;
pub use crate::streaming::StreamingNoiseLink;
pub use crate::transport::NoiseTransport;

// Error handling
pub use crate::errors::{NoiseError, NoiseErrorCode, NoiseResult};

// Key management
pub use crate::ring::{DummyRing, RingKeyFiller, RingKeyProvider};

// Session management
pub use crate::session_id::SessionId;
pub use crate::session_manager::{NoiseRole, NoiseSessionManager, ThreadSafeSessionManager};

// Mobile/manager
pub use crate::mobile_manager::{ConnectionStatus, MobileConfig, NoiseManager, SessionState};

// Rate limiting
pub use crate::rate_limiter::{RateLimitReason, RateLimitResult, RateLimiter, RateLimiterConfig};

// Identity
pub use crate::identity_payload::BindingMessageParams;

// Conditional re-exports
#[cfg(feature = "pkarr")]
pub use crate::pkarr::{DummyPkarr, PkarrNoiseRecord, PkarrResolver};

#[cfg(feature = "pubky-sdk")]
pub use crate::pubky_ring::PubkyRingProvider;

#[cfg(feature = "storage-queue")]
pub use crate::storage_queue::{MessageQueue, RetryConfig, StorageBackedMessaging};
