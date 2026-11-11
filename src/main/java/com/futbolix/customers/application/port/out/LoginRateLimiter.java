package com.futbolix.customers.application.port.out;

import java.time.Duration;
import java.time.Instant;

/** Login attempts per client address (security-rules.md A07: 10 per IP in 5 minutes). */
public interface LoginRateLimiter {

    /** Counts one attempt; empty when allowed, otherwise how long the client must wait. */
    java.util.Optional<Duration> tryAcquire(String clientAddress, Instant now);
}
