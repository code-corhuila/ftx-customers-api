package com.futbolix.customers.adapter.out.security;

import com.futbolix.customers.application.port.out.LoginRateLimiter;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding window per client address, in memory: 10 attempts in 5 minutes by default
 * (security-rules.md A07). One instance per service replica, which is enough for the MVP (one
 * replica); the gateway applies its own limit in front of it (ftx-docs#51). The number of tracked
 * addresses is capped so a flood of distinct addresses cannot exhaust memory.
 */
public class InMemoryLoginRateLimiter implements LoginRateLimiter {

    private static final int MAX_TRACKED_ADDRESSES = 10_000;

    private final int maxAttempts;
    private final Duration window;
    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

    public InMemoryLoginRateLimiter(int maxAttempts, Duration window) {
        if (maxAttempts < 1 || window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("maxAttempts must be at least 1 and window positive");
        }
        this.maxAttempts = maxAttempts;
        this.window = window;
    }

    @Override
    public Optional<Duration> tryAcquire(String clientAddress, Instant now) {
        String key = clientAddress == null ? "unknown" : clientAddress;
        if (attempts.size() >= MAX_TRACKED_ADDRESSES && !attempts.containsKey(key)) {
            evictExpired(now);
        }
        Deque<Instant> times = attempts.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (times) {
            Instant from = now.minus(window);
            while (!times.isEmpty() && !times.peekFirst().isAfter(from)) {
                times.pollFirst();
            }
            if (times.size() >= maxAttempts) {
                Duration wait = Duration.between(now, times.peekFirst().plus(window));
                return Optional.of(wait.isNegative() || wait.isZero() ? Duration.ofSeconds(1) : wait);
            }
            times.addLast(now);
            return Optional.empty();
        }
    }

    private void evictExpired(Instant now) {
        Instant from = now.minus(window);
        attempts.entrySet().removeIf(e -> {
            synchronized (e.getValue()) {
                Instant last = e.getValue().peekLast();
                return last == null || !last.isAfter(from);
            }
        });
    }
}
