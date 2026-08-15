//! Per-source-address rate limiting for the unauthenticated authentication endpoints.
//!
//! The credential softlock (see `kanidmd_lib::credential::softlock`) already throttles guessing
//! against a *known* account, but it only engages once an auth session has selected a credential.
//! The `init` step - which resolves a name to an account - is reachable by anyone who can open a
//! socket, so without a limiter here an attacker can probe names as fast as the server will answer.
//!
//! This is deliberately a coarse token bucket rather than a precise quota. The goal is to make
//! bulk automated probing expensive while leaving real logins (including many users behind one
//! NAT or reverse proxy) unaffected, so the defaults are permissive.

// A BTreeMap rather than a HashMap: std's HashMap is a disallowed type here (see clippy.toml),
// concread is built for read-mostly access where this mutates on every request, and the map is
// capped at SWEEP_THRESHOLD entries so the log-n lookup cost is irrelevant.
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use sketching::*;

use crate::https::extractors::ClientConnInfo;
use crate::https::ServerState;

/// Below this many tracked sources, sweeping is not worth the scan.
const SWEEP_THRESHOLD: usize = 8192;
/// Minimum interval between sweeps. The sweep is O(n), so gating it on time keeps the per-request
/// cost amortised - without this, every request past the threshold pays for a full scan.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Backstop if sweeping somehow fails to reclaim. Reaching this means the eviction rule below is
/// wrong, so we drop everything rather than let the limiter exhaust memory.
const HARD_MAX: usize = 262_144;

/// Fallback when `per_second` is configured as something a bucket could never refill from.
const PER_SEC_FALLBACK: f64 = 2.0;

struct Bucket {
    /// Tokens remaining, as a float so partial refills accumulate.
    tokens: f64,
    last_seen: Instant,
}

struct LimiterState {
    buckets: BTreeMap<IpAddr, Bucket>,
    last_sweep: Instant,
}

pub struct AuthRateLimiter {
    inner: Mutex<LimiterState>,
    burst: f64,
    per_sec: f64,
}

/// Tokens `bucket` would hold at `now`, capped at `burst`.
///
/// A bucket sitting at the cap carries no state that a freshly created bucket would not, which is
/// what makes it safe to evict during a sweep.
fn refilled_tokens(bucket: &Bucket, now: Instant, burst: f64, per_sec: f64) -> f64 {
    // Instant::duration_since saturates to zero rather than panicking if now precedes last_seen.
    let elapsed = now.duration_since(bucket.last_seen).as_secs_f64();
    (bucket.tokens + (elapsed * per_sec)).min(burst)
}

impl AuthRateLimiter {
    pub fn new(burst: u32, per_sec: f64) -> Self {
        // Misconfiguration here fails silently closed - a zero burst or a rate that never refills
        // denies every authentication attempt on the server. Clamp to something usable and say so
        // loudly rather than locking every user out over a typo.
        let burst = if burst == 0 {
            warn!("auth_ratelimit.burst of 0 would deny all authentication, using 1 instead");
            1.0
        } else {
            f64::from(burst)
        };

        let per_sec = if per_sec.is_finite() && per_sec > 0.0 {
            per_sec
        } else {
            warn!(
                ?per_sec,
                "auth_ratelimit.per_second must be a positive finite number, using {PER_SEC_FALLBACK} instead"
            );
            PER_SEC_FALLBACK
        };

        AuthRateLimiter {
            inner: Mutex::new(LimiterState {
                buckets: BTreeMap::new(),
                last_sweep: Instant::now(),
            }),
            burst,
            per_sec,
        }
    }

    /// Take a token for `addr`, returning false when the source has exhausted its budget.
    fn check(&self, addr: IpAddr, now: Instant) -> bool {
        let burst = self.burst;
        let per_sec = self.per_sec;

        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // A panic elsewhere must not wedge authentication for everyone - recover the map
                // rather than propagating the poison.
                poisoned.into_inner()
            }
        };
        let state = &mut *guard;

        if state.buckets.len() > SWEEP_THRESHOLD
            && now.duration_since(state.last_sweep) >= SWEEP_INTERVAL
        {
            // Keep only the sources still carrying debt. Anything that has refilled to the cap is
            // free to forget, because recreating it yields an identical full bucket - so this
            // reclaims regardless of how recently a source was seen. Holding N entries therefore
            // costs an attacker N sources each sustaining more than per_sec requests/second.
            state
                .buckets
                .retain(|_, bucket| refilled_tokens(bucket, now, burst, per_sec) < burst);
            state.last_sweep = now;

            if state.buckets.len() > HARD_MAX {
                error!(
                    tracked = state.buckets.len(),
                    "Authentication rate limit table exceeded its bound after sweeping - resetting. \
                     Every source regains a full burst; this should not be reachable."
                );
                state.buckets.clear();
            }
        }

        let bucket = state.buckets.entry(addr).or_insert(Bucket {
            tokens: burst,
            last_seen: now,
        });

        bucket.tokens = refilled_tokens(bucket, now, burst, per_sec);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Rate limit the unauthenticated auth endpoints per source address.
///
/// Applied as a route layer so it only covers the authentication surface - the rest of the API is
/// authenticated and already accounted for elsewhere.
pub async fn auth_rate_limit_layer(
    State(state): State<ServerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(limiter) = state.auth_ratelimit.as_ref() else {
        return next.run(request).await;
    };

    // ip_address_middleware has already resolved proxy-protocol / x-forwarded-for into a trusted
    // client address by this point. If it is absent we are not in a position to attribute the
    // request, so fail closed rather than handing out an unmetered path.
    let Some(conn_info) = request.extensions().get::<ClientConnInfo>() else {
        error!("Client connection info missing - unable to rate limit authentication request");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to attribute request",
        )
            .into_response();
    };

    let client_ip_addr = conn_info.client_ip_addr;

    if limiter.check(client_ip_addr, Instant::now()) {
        next.run(request).await
    } else {
        security_info!(
            %client_ip_addr,
            "Rate limit exceeded on authentication endpoint",
        );
        (
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded, slow down",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratelimit_burst_then_throttle() {
        let limiter = AuthRateLimiter::new(3, 1.0);
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let now = Instant::now();

        // The burst is spendable immediately.
        for _ in 0..3 {
            assert!(limiter.check(addr, now));
        }
        // And then we are throttled.
        assert!(!limiter.check(addr, now));
    }

    #[test]
    fn test_ratelimit_refills_over_time() {
        let limiter = AuthRateLimiter::new(2, 1.0);
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let now = Instant::now();

        assert!(limiter.check(addr, now));
        assert!(limiter.check(addr, now));
        assert!(!limiter.check(addr, now));

        // One second later, one token has refilled - but only one.
        let later = now + Duration::from_secs(1);
        assert!(limiter.check(addr, later));
        assert!(!limiter.check(addr, later));
    }

    #[test]
    fn test_ratelimit_refill_caps_at_burst() {
        let limiter = AuthRateLimiter::new(2, 1.0);
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let now = Instant::now();

        // A long idle period must not accrue more than the burst.
        let later = now + Duration::from_secs(3600);
        assert!(limiter.check(addr, later));
        assert!(limiter.check(addr, later));
        assert!(!limiter.check(addr, later));
    }

    #[test]
    fn test_ratelimit_is_per_source() {
        let limiter = AuthRateLimiter::new(1, 1.0);
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        let now = Instant::now();

        assert!(limiter.check(a, now));
        assert!(!limiter.check(a, now));
        // b has its own budget and is unaffected by a exhausting theirs.
        assert!(limiter.check(b, now));
    }

    fn tracked(limiter: &AuthRateLimiter) -> usize {
        limiter.inner.lock().unwrap().buckets.len()
    }

    /// Fill past the sweep threshold, one request from each of many distinct sources.
    fn fill_past_threshold(limiter: &AuthRateLimiter, now: Instant) {
        for i in 0..=SWEEP_THRESHOLD {
            let addr = IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
            assert!(limiter.check(addr, now));
        }
    }

    #[test]
    fn test_ratelimit_sweeps_refilled_entries() {
        let limiter = AuthRateLimiter::new(1, 1.0);
        let now = Instant::now();

        fill_past_threshold(&limiter, now);
        assert!(tracked(&limiter) > SWEEP_THRESHOLD);

        // Once those buckets have refilled they carry no state, so a later request reclaims them.
        let later = now + SWEEP_INTERVAL + Duration::from_secs(1);
        let fresh: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(limiter.check(fresh, later));
        assert_eq!(tracked(&limiter), 1);
    }

    /// A prober rotating through fresh addresses must not accumulate an entry per address seen.
    ///
    /// Evicting on idle time alone does not achieve this: entries linger for the whole idle window
    /// regardless of whether they still carry any limiting state, so the table grows with the
    /// prober's address churn. Evicting anything that has refilled to the cap bounds the table at
    /// roughly one sweep interval's worth of sources instead.
    #[test]
    fn test_ratelimit_bounded_under_address_rotation() {
        const ROUNDS: usize = 10;
        const PER_ROUND: usize = 3000;

        let limiter = AuthRateLimiter::new(1, 1.0);
        let start = Instant::now();

        for round in 0..ROUNDS {
            // Each round is a full sweep interval later, with an entirely new set of sources.
            let at = start + (SWEEP_INTERVAL + Duration::from_secs(1)) * (round as u32);
            for i in 0..PER_ROUND {
                let addr = IpAddr::from([10, round as u8, (i >> 8) as u8, i as u8]);
                limiter.check(addr, at);
            }
        }

        // The sweep is size-gated, so the table oscillates up to the threshold and back rather
        // than tracking every address ever seen. Anything approaching ROUNDS * PER_ROUND means
        // eviction is not keeping up with churn.
        let bound = SWEEP_THRESHOLD + PER_ROUND;
        assert!(
            tracked(&limiter) <= bound,
            "table grew with address churn: {} entries (bound {}) after {} rounds of {}",
            tracked(&limiter),
            bound,
            ROUNDS,
            PER_ROUND
        );
    }

    /// A zero burst would otherwise deny every authentication attempt on the server.
    #[test]
    fn test_ratelimit_rejects_lockout_config() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let now = Instant::now();

        assert!(AuthRateLimiter::new(0, 1.0).check(addr, now));

        for bad_rate in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let limiter = AuthRateLimiter::new(1, bad_rate);
            assert!(
                limiter.check(addr, now),
                "rate {bad_rate} denied first request"
            );
            // And it must still refill rather than latching shut.
            assert!(limiter.check(addr, now + Duration::from_secs(10)));
        }
    }
}
