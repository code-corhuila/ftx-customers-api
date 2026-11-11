package com.futbolix.customers.domain;

import java.time.Duration;
import java.time.Instant;

/**
 * Lockout rule of 00-governance/security-rules.md (A07): after 5 consecutive failed logins the
 * account is locked for a while. The counter restarts after the lock and after a successful login.
 * The lock duration is not fixed by the documentation; ADR-012 sets 15 minutes.
 */
public record LoginPolicy(int maxConsecutiveFailures, Duration lockDuration) {

    public static final LoginPolicy DEFAULT = new LoginPolicy(5, Duration.ofMinutes(15));

    public LoginPolicy {
        if (maxConsecutiveFailures < 1) {
            throw new IllegalArgumentException("maxConsecutiveFailures must be at least 1");
        }
        if (lockDuration == null || lockDuration.isNegative() || lockDuration.isZero()) {
            throw new IllegalArgumentException("lockDuration must be positive");
        }
    }

    /** The account after one more failed login at {@code now}. */
    public Administrator afterFailure(Administrator account, Instant now) {
        int failures = account.failedLoginCount() + 1;
        if (failures >= maxConsecutiveFailures) {
            return copy(account, 0, now.plus(lockDuration));
        }
        return copy(account, failures, account.lockedUntil());
    }

    /** The account after a successful login: no failures, no lock. */
    public Administrator afterSuccess(Administrator account) {
        return copy(account, 0, null);
    }

    private static Administrator copy(Administrator a, int failures, Instant lockedUntil) {
        return new Administrator(a.id(), a.fullName(), a.email(), a.passwordHash(), a.role(), failures, lockedUntil);
    }
}
