pub mod errors;
pub mod types;
pub mod manager;
pub mod config;

use crate::{NoiseError, NoiseErrorCode};

// Re-export core types for internal FFI usage
pub use types::*;
pub use errors::*;
pub use manager::*;
pub use config::*;

// Initialize uniffi scaffolding
uniffi::include_scaffolding!("pubky_noise");

