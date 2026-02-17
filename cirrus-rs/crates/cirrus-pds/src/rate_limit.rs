//! Rate limiting using the token bucket algorithm.
//!
//! Provides IP-keyed rate limiters for general endpoints and
//! stricter limits for authentication endpoints.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use crate::error::PdsError;

/// Keyed rate limiter indexed by IP address.
pub type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second for general endpoints.
    pub general_rps: u32,
    /// Requests per second for login attempts.
    pub login_rps: u32,
    /// Burst size multiplier applied to the per-second rate.
    pub burst_multiplier: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            general_rps: 30,
            login_rps: 5,
            burst_multiplier: 3,
        }
    }
}

/// Shared rate limit state for the PDS server.
pub struct RateLimitState {
    /// General endpoint limiter.
    pub general: Arc<KeyedLimiter>,
    /// Login endpoint limiter (stricter).
    pub login: Arc<KeyedLimiter>,
}

impl RateLimitState {
    /// Creates rate limit state from configuration.
    #[must_use]
    pub fn from_config(config: &RateLimitConfig) -> Self {
        Self {
            general: Arc::new(create_keyed_limiter(
                config.general_rps,
                config.general_rps.saturating_mul(config.burst_multiplier),
            )),
            login: Arc::new(create_keyed_limiter(
                config.login_rps,
                config.login_rps.saturating_mul(config.burst_multiplier),
            )),
        }
    }
}

impl Default for RateLimitState {
    fn default() -> Self {
        Self::from_config(&RateLimitConfig::default())
    }
}

/// Checks whether a request from the given IP is allowed by the limiter.
///
/// # Errors
/// Returns `PdsError::RateLimited` if the rate limit is exceeded.
pub fn check_rate_limit(limiter: &KeyedLimiter, ip: IpAddr) -> crate::error::Result<()> {
    limiter.check_key(&ip).map_err(|_| PdsError::RateLimited)
}

fn create_keyed_limiter(rps: u32, burst: u32) -> KeyedLimiter {
    let rps = NonZeroU32::new(rps).unwrap_or(NonZeroU32::MIN);
    let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
    let quota = Quota::per_second(rps).allow_burst(burst);
    RateLimiter::keyed(quota)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.general_rps, 30);
        assert_eq!(config.login_rps, 5);
        assert_eq!(config.burst_multiplier, 3);
    }

    #[test]
    fn test_rate_limit_state_creation() {
        let state = RateLimitState::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // First request should succeed
        assert!(check_rate_limit(&state.general, ip).is_ok());
        assert!(check_rate_limit(&state.login, ip).is_ok());
    }

    #[test]
    fn test_rate_limit_exhaustion() {
        let config = RateLimitConfig {
            general_rps: 1,
            login_rps: 1,
            burst_multiplier: 1,
        };
        let state = RateLimitState::from_config(&config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // First request uses the burst allowance
        assert!(check_rate_limit(&state.login, ip).is_ok());

        // Second request should be rate limited (burst=1, already used)
        assert!(check_rate_limit(&state.login, ip).is_err());
    }

    #[test]
    fn test_rate_limit_different_ips() {
        let config = RateLimitConfig {
            general_rps: 1,
            login_rps: 1,
            burst_multiplier: 1,
        };
        let state = RateLimitState::from_config(&config);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1
        assert!(check_rate_limit(&state.login, ip1).is_ok());
        assert!(check_rate_limit(&state.login, ip1).is_err());

        // ip2 should still be allowed
        assert!(check_rate_limit(&state.login, ip2).is_ok());
    }
}
