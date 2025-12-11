//! Rate limiting for Noise protocol servers.
//!
//! This module provides configurable rate limiting to protect servers from
//! denial-of-service attacks and excessive handshake attempts.
//!
//! ## Usage
//!
//! ```rust
//! use pubky_noise::rate_limiter::{RateLimiter, RateLimiterConfig};
//! use std::net::IpAddr;
//!
//! let config = RateLimiterConfig::default();
//! let limiter = RateLimiter::new(config);
//!
//! let client_ip: IpAddr = "192.168.1.1".parse().unwrap();
//!
//! // Check if handshake is allowed
//! if limiter.check_handshake(&client_ip) {
//!     // Process handshake
//! } else {
//!     // Reject - rate limited
//! }
//!
//! // Record successful handshake
//! limiter.record_handshake(&client_ip);
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Configuration for the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum handshake attempts per IP within the window.
    pub max_handshakes_per_ip: u32,

    /// Time window in seconds for rate limiting.
    pub window_secs: u64,

    /// Minimum milliseconds between handshake attempts from same IP.
    pub handshake_cooldown_ms: u64,

    /// Maximum number of IPs to track (prevents memory exhaustion).
    pub max_tracked_ips: usize,

    /// How often to clean up expired entries (in seconds).
    pub cleanup_interval_secs: u64,

    /// Whether rate limiting is enabled.
    pub enabled: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_handshakes_per_ip: 10,
            window_secs: 60,
            handshake_cooldown_ms: 100,
            max_tracked_ips: 10_000,
            cleanup_interval_secs: 60,
            enabled: true,
        }
    }
}

impl RateLimiterConfig {
    /// Create a strict configuration for high-security environments.
    pub fn strict() -> Self {
        Self {
            max_handshakes_per_ip: 3,
            window_secs: 60,
            handshake_cooldown_ms: 500,
            max_tracked_ips: 5_000,
            cleanup_interval_secs: 30,
            enabled: true,
        }
    }

    /// Create a lenient configuration for trusted environments.
    pub fn lenient() -> Self {
        Self {
            max_handshakes_per_ip: 100,
            window_secs: 60,
            handshake_cooldown_ms: 10,
            max_tracked_ips: 50_000,
            cleanup_interval_secs: 120,
            enabled: true,
        }
    }

    /// Disable rate limiting entirely.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Tracking data for a single IP address.
#[derive(Debug, Clone)]
struct IpTracker {
    /// Timestamps of handshake attempts within the current window.
    attempts: Vec<Instant>,

    /// Last handshake attempt time (for cooldown).
    last_attempt: Instant,
}

impl IpTracker {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            // Set to a time in the past so first attempt isn't blocked by cooldown
            last_attempt: Instant::now() - Duration::from_secs(3600),
        }
    }

    /// Prune attempts older than the window.
    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.attempts.retain(|t| *t > cutoff);
    }

    /// Check if a new attempt is allowed.
    fn is_allowed(&self, max_attempts: u32, cooldown: Duration) -> bool {
        // Check cooldown (only if we've had any attempts)
        if !self.attempts.is_empty() && self.last_attempt.elapsed() < cooldown {
            return false;
        }

        // Check rate limit
        self.attempts.len() < max_attempts as usize
    }

    /// Record a new attempt.
    fn record_attempt(&mut self) {
        let now = Instant::now();
        self.attempts.push(now);
        self.last_attempt = now;
    }
}

/// Thread-safe rate limiter for Noise protocol handshakes.
pub struct RateLimiter {
    config: RateLimiterConfig,
    trackers: Mutex<HashMap<IpAddr, IpTracker>>,
    last_cleanup: Mutex<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            trackers: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Create a rate limiter with default configuration.
    pub fn default_config() -> Self {
        Self::new(RateLimiterConfig::default())
    }

    /// Check if a handshake from the given IP is allowed.
    ///
    /// Returns `true` if the handshake should be processed, `false` if rate limited.
    pub fn check_handshake(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }

        self.maybe_cleanup();

        let mut trackers = self.trackers.lock().unwrap();
        let window = Duration::from_secs(self.config.window_secs);
        let cooldown = Duration::from_millis(self.config.handshake_cooldown_ms);

        if let Some(tracker) = trackers.get_mut(ip) {
            tracker.prune(window);
            tracker.is_allowed(self.config.max_handshakes_per_ip, cooldown)
        } else {
            // First attempt from this IP
            true
        }
    }

    /// Record a handshake attempt from the given IP.
    ///
    /// Call this after processing a handshake (whether successful or not).
    pub fn record_handshake(&self, ip: &IpAddr) {
        if !self.config.enabled {
            return;
        }

        let mut trackers = self.trackers.lock().unwrap();

        // Enforce max tracked IPs
        if trackers.len() >= self.config.max_tracked_ips && !trackers.contains_key(ip) {
            // Remove oldest entry (simple eviction)
            if let Some(oldest_ip) = trackers
                .iter()
                .min_by_key(|(_, t)| t.last_attempt)
                .map(|(ip, _)| *ip)
            {
                trackers.remove(&oldest_ip);
            }
        }

        let tracker = trackers.entry(*ip).or_insert_with(IpTracker::new);
        tracker.record_attempt();
    }

    /// Check and record in one atomic operation.
    ///
    /// Returns `true` if the handshake is allowed (and records it).
    /// Returns `false` if rate limited (does not record).
    pub fn check_and_record(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }

        self.maybe_cleanup();

        let mut trackers = self.trackers.lock().unwrap();
        let window = Duration::from_secs(self.config.window_secs);
        let cooldown = Duration::from_millis(self.config.handshake_cooldown_ms);

        // Enforce max tracked IPs
        if trackers.len() >= self.config.max_tracked_ips && !trackers.contains_key(ip) {
            if let Some(oldest_ip) = trackers
                .iter()
                .min_by_key(|(_, t)| t.last_attempt)
                .map(|(ip, _)| *ip)
            {
                trackers.remove(&oldest_ip);
            }
        }

        let tracker = trackers.entry(*ip).or_insert_with(IpTracker::new);
        tracker.prune(window);

        if tracker.is_allowed(self.config.max_handshakes_per_ip, cooldown) {
            tracker.record_attempt();
            true
        } else {
            false
        }
    }

    /// Get the current number of tracked IPs.
    pub fn tracked_ip_count(&self) -> usize {
        self.trackers.lock().unwrap().len()
    }

    /// Get remaining attempts for an IP within the current window.
    pub fn remaining_attempts(&self, ip: &IpAddr) -> u32 {
        if !self.config.enabled {
            return u32::MAX;
        }

        let mut trackers = self.trackers.lock().unwrap();
        let window = Duration::from_secs(self.config.window_secs);

        if let Some(tracker) = trackers.get_mut(ip) {
            tracker.prune(window);
            self.config
                .max_handshakes_per_ip
                .saturating_sub(tracker.attempts.len() as u32)
        } else {
            self.config.max_handshakes_per_ip
        }
    }

    /// Clear all rate limiting data.
    pub fn clear(&self) {
        self.trackers.lock().unwrap().clear();
    }

    /// Run cleanup of expired entries.
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.lock().unwrap();
            last.elapsed() >= Duration::from_secs(self.config.cleanup_interval_secs)
        };

        if should_cleanup {
            self.cleanup();
        }
    }

    /// Force cleanup of expired entries.
    pub fn cleanup(&self) {
        let window = Duration::from_secs(self.config.window_secs);
        let mut trackers = self.trackers.lock().unwrap();

        trackers.retain(|_, tracker| {
            tracker.prune(window);
            !tracker.attempts.is_empty()
        });

        *self.last_cleanup.lock().unwrap() = Instant::now();
    }

    /// Get the configuration.
    pub fn config(&self) -> &RateLimiterConfig {
        &self.config
    }
}

/// Result type for rate limit checks with detailed information.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,

    /// Remaining attempts in the current window.
    pub remaining: u32,

    /// Time until the rate limit resets (if limited).
    pub retry_after: Option<Duration>,

    /// Reason for denial (if denied).
    pub reason: Option<RateLimitReason>,
}

/// Reason for rate limit denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    /// Too many attempts within the time window.
    TooManyAttempts,

    /// Request came too quickly after the previous one.
    CooldownActive,
}

impl RateLimiter {
    /// Check handshake with detailed result.
    pub fn check_handshake_detailed(&self, ip: &IpAddr) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                retry_after: None,
                reason: None,
            };
        }

        self.maybe_cleanup();

        let mut trackers = self.trackers.lock().unwrap();
        let window = Duration::from_secs(self.config.window_secs);
        let cooldown = Duration::from_millis(self.config.handshake_cooldown_ms);

        if let Some(tracker) = trackers.get_mut(ip) {
            tracker.prune(window);

            let cooldown_remaining = cooldown.saturating_sub(tracker.last_attempt.elapsed());
            if !cooldown_remaining.is_zero() {
                return RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    retry_after: Some(cooldown_remaining),
                    reason: Some(RateLimitReason::CooldownActive),
                };
            }

            let remaining = self
                .config
                .max_handshakes_per_ip
                .saturating_sub(tracker.attempts.len() as u32);

            if remaining == 0 {
                // Find when the oldest attempt will expire
                let retry_after = tracker
                    .attempts
                    .first()
                    .map(|oldest| window.saturating_sub(oldest.elapsed()));

                return RateLimitResult {
                    allowed: false,
                    remaining: 0,
                    retry_after,
                    reason: Some(RateLimitReason::TooManyAttempts),
                };
            }

            RateLimitResult {
                allowed: true,
                remaining,
                retry_after: None,
                reason: None,
            }
        } else {
            RateLimitResult {
                allowed: true,
                remaining: self.config.max_handshakes_per_ip,
                retry_after: None,
                reason: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_basic_rate_limiting() {
        let config = RateLimiterConfig {
            max_handshakes_per_ip: 3,
            window_secs: 60,
            handshake_cooldown_ms: 0, // Disable cooldown for test
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 3 attempts should be allowed
        assert!(limiter.check_and_record(&ip));
        assert!(limiter.check_and_record(&ip));
        assert!(limiter.check_and_record(&ip));

        // 4th attempt should be denied
        assert!(!limiter.check_and_record(&ip));

        // Different IP should still work
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(limiter.check_and_record(&ip2));
    }

    #[test]
    fn test_cooldown() {
        let config = RateLimiterConfig {
            max_handshakes_per_ip: 10,
            handshake_cooldown_ms: 50,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First attempt allowed
        assert!(limiter.check_and_record(&ip));

        // Immediate second attempt should be denied (cooldown)
        assert!(!limiter.check_handshake(&ip));

        // Wait for cooldown (with extra margin for timing variance)
        thread::sleep(Duration::from_millis(100));

        // Now should be allowed
        assert!(limiter.check_and_record(&ip));
    }

    #[test]
    fn test_disabled() {
        let config = RateLimiterConfig::disabled();
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // All attempts should be allowed
        for _ in 0..100 {
            assert!(limiter.check_and_record(&ip));
        }
    }

    #[test]
    fn test_detailed_result() {
        let config = RateLimiterConfig {
            max_handshakes_per_ip: 2,
            handshake_cooldown_ms: 0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let result = limiter.check_handshake_detailed(&ip);
        assert!(result.allowed);
        assert_eq!(result.remaining, 2);

        limiter.record_handshake(&ip);
        let result = limiter.check_handshake_detailed(&ip);
        assert!(result.allowed);
        assert_eq!(result.remaining, 1);

        limiter.record_handshake(&ip);
        let result = limiter.check_handshake_detailed(&ip);
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.reason, Some(RateLimitReason::TooManyAttempts));
    }

    #[test]
    fn test_max_tracked_ips() {
        let config = RateLimiterConfig {
            max_tracked_ips: 3,
            handshake_cooldown_ms: 0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Fill up to max
        for i in 1..=3 {
            let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
            limiter.record_handshake(&ip);
        }
        assert_eq!(limiter.tracked_ip_count(), 3);

        // Adding new IP should evict oldest
        let ip4: IpAddr = "192.168.1.4".parse().unwrap();
        limiter.record_handshake(&ip4);
        assert_eq!(limiter.tracked_ip_count(), 3);
    }

    #[test]
    fn test_cleanup() {
        let config = RateLimiterConfig {
            window_secs: 1, // Very short window for testing
            handshake_cooldown_ms: 0,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        limiter.record_handshake(&ip);
        assert_eq!(limiter.tracked_ip_count(), 1);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        limiter.cleanup();
        assert_eq!(limiter.tracked_ip_count(), 0);
    }
}
