package com.futbolix.customers.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** security-rules.md A07: at most 10 login attempts per address in 5 minutes. */
class InMemoryLoginRateLimiterTest {

    static final Instant T0 = Instant.parse("2026-11-11T15:00:00Z");
    final InMemoryLoginRateLimiter limiter = new InMemoryLoginRateLimiter(10, Duration.ofMinutes(5));

    @Test
    void allowsTenAttemptsThenTellsHowLongToWait() {
        for (int i = 0; i < 10; i++) {
            assertThat(limiter.tryAcquire("1.1.1.1", T0.plusSeconds(i))).isEmpty();
        }
        assertThat(limiter.tryAcquire("1.1.1.1", T0.plusSeconds(10))).contains(Duration.ofSeconds(290));
    }

    @Test
    void theWindowSlides() {
        for (int i = 0; i < 10; i++) {
            limiter.tryAcquire("1.1.1.1", T0);
        }
        assertThat(limiter.tryAcquire("1.1.1.1", T0.plus(Duration.ofMinutes(5)))).isEmpty();
    }

    @Test
    void addressesAreCountedSeparately() {
        for (int i = 0; i < 10; i++) {
            limiter.tryAcquire("1.1.1.1", T0);
        }
        assertThat(limiter.tryAcquire("2.2.2.2", T0)).isEmpty();
    }
}
