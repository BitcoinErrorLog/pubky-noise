# Production Deployment Guide

This guide covers deploying Pubky Noise in production environments.

## Pre-Deployment Checklist

- [ ] Security audit completed
- [ ] Rate limiting configured
- [ ] Key management reviewed
- [ ] Logging and monitoring set up
- [ ] Error handling tested
- [ ] Performance benchmarks run
- [ ] Backup and recovery plan

## Configuration

### Server Configuration

```rust
use pubky_noise::{NoiseServer, ServerPolicy, RateLimiter, RateLimiterConfig};
use std::sync::Arc;

// Production server policy
let policy = ServerPolicy::default()
    .with_max_sessions_per_identity(10)
    .with_session_timeout_secs(3600)
    .with_require_identity_proof(true);

// Strict rate limiting for production
let rate_limiter = Arc::new(RateLimiter::new(RateLimiterConfig::strict()));

let server = NoiseServer::new(key_provider)
    .with_policy(policy)
    .with_rate_limiter(rate_limiter);
```

### Recommended Rate Limits

| Environment | Max Attempts | Cooldown | Max IPs |
|-------------|--------------|----------|---------|
| Production  | 5            | 60s      | 100,000 |
| Staging     | 10           | 30s      | 10,000  |
| Development | 100          | 1s       | 1,000   |

## Performance Tuning

### Memory Management

```rust
// Configure session cleanup intervals
let config = MobileConfig {
    session_cleanup_interval_ms: 60_000,  // 1 minute
    max_cached_sessions: 1000,
    // ...
};
```

### Connection Pooling

For high-throughput scenarios, use connection pooling:

```rust
use std::collections::HashMap;
use std::sync::RwLock;

struct ConnectionPool {
    connections: RwLock<HashMap<String, NoiseLink>>,
    max_connections: usize,
}
```

### Performance Benchmarks

Expected performance on modern hardware:

| Operation | Latency (p50) | Latency (p99) | Throughput |
|-----------|---------------|---------------|------------|
| IK Handshake | 2ms | 10ms | 5,000/sec |
| XX Handshake | 4ms | 15ms | 2,500/sec |
| Encrypt (1KB) | 50μs | 200μs | 100,000/sec |
| Decrypt (1KB) | 50μs | 200μs | 100,000/sec |

### Benchmarking Your Deployment

```bash
# Run built-in benchmarks
cargo bench

# Profile with flamegraph
cargo flamegraph --bench handshake_bench
```

## Security Hardening

### Key Management

1. **Never hardcode keys** - Use environment variables or secure vaults
2. **Rotate keys regularly** - Implement key rotation policies
3. **Use HSM for signing** - Hardware security modules for production

```rust
// Load keys from environment
let private_key = std::env::var("NOISE_PRIVATE_KEY")
    .expect("NOISE_PRIVATE_KEY must be set");

let key_bytes = hex::decode(private_key)?;
```

### Network Security

1. **TLS everywhere** - Use TLS for transport even with Noise encryption
2. **IP allowlisting** - Restrict server access where possible
3. **DDoS protection** - Use rate limiting and connection limits

### Audit Logging

```rust
use tracing::{info, warn, error};

// Log all connection attempts
info!(
    peer_id = %peer_id,
    ip = %client_ip,
    "Connection established"
);

// Log security events
warn!(
    peer_id = %peer_id,
    ip = %client_ip,
    reason = "rate_limited",
    "Connection rejected"
);
```

## Monitoring

### Metrics to Track

- Active sessions count
- Handshake success/failure rate
- Message throughput
- Latency percentiles
- Rate limit triggers
- Error rates by type

### Health Checks

```rust
// Implement health endpoint
async fn health_check(manager: &NoiseManager) -> HealthStatus {
    HealthStatus {
        active_sessions: manager.session_count(),
        uptime_secs: manager.uptime().as_secs(),
        rate_limit_remaining: manager.rate_limit_remaining(),
    }
}
```

### Alerting Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Active Sessions | >80% capacity | >95% capacity |
| Error Rate | >1% | >5% |
| Handshake Latency (p99) | >100ms | >500ms |
| Rate Limit Triggers | >100/min | >1000/min |

## High Availability

### Session Replication

For HA deployments, implement session state sharing:

```rust
// Use Redis or similar for session state
trait SessionStore {
    async fn save(&self, session: &SessionState) -> Result<()>;
    async fn load(&self, id: &SessionId) -> Result<Option<SessionState>>;
}
```

### Load Balancing

- Use sticky sessions based on client ID
- Or implement session state sharing across nodes
- Health check endpoints for load balancer

### Graceful Shutdown

```rust
async fn shutdown(manager: &NoiseManager) {
    // Stop accepting new connections
    manager.stop_accepting();
    
    // Wait for active sessions to complete
    manager.wait_for_completion(Duration::from_secs(30)).await;
    
    // Force close remaining
    manager.force_close_all();
}
```

## Troubleshooting

### Common Production Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Memory growth | Session leak | Check cleanup intervals |
| High latency | CPU saturation | Scale horizontally |
| Connection drops | Network issues | Check keep-alives |
| Rate limit storms | DDoS attack | Increase limits or add WAF |

### Debug Commands

```bash
# Check active connections
curl localhost:8080/debug/sessions

# Get rate limit status
curl localhost:8080/debug/rate-limits

# Force cleanup
curl -X POST localhost:8080/admin/cleanup
```

## Disaster Recovery

### Backup Strategy

1. **Key backup** - Secure offline backup of signing keys
2. **Configuration** - Version control all config
3. **Session state** - Consider ephemeral (no backup needed)

### Recovery Procedure

1. Deploy new instance
2. Restore keys from backup
3. Update DNS/load balancer
4. Verify connectivity
5. Monitor for errors

## Compliance

### Data Handling

- Noise sessions are ephemeral
- No PII stored by default
- Logs may contain IP addresses

### Regulatory Considerations

- GDPR: Implement data deletion on request
- SOC2: Enable comprehensive audit logging
- HIPAA: Consider additional encryption at rest
