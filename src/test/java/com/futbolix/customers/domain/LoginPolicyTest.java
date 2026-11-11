package com.futbolix.customers.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class LoginPolicyTest {

    static final Instant NOW = Instant.parse("2026-11-11T15:00:00Z");
    final Administrator fresh = new Administrator(UUID.randomUUID(), "Admin", "admin@example.test",
            "$2a$12$" + "a".repeat(53), Administrator.ADMINISTRATOR, 0, null);

    @Test
    void theFifthConsecutiveFailureLocksForFifteenMinutesAndRestartsTheCounter() {
        Administrator a = fresh;
        for (int i = 1; i <= 4; i++) {
            a = LoginPolicy.DEFAULT.afterFailure(a, NOW);
            assertThat(a.failedLoginCount()).isEqualTo(i);
            assertThat(a.isLocked(NOW)).isFalse();
        }
        a = LoginPolicy.DEFAULT.afterFailure(a, NOW);

        assertThat(a.failedLoginCount()).isZero();
        assertThat(a.lockedUntil()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(a.isLocked(NOW.plus(Duration.ofMinutes(14)))).isTrue();
        assertThat(a.isLocked(NOW.plus(Duration.ofMinutes(15)))).isFalse();
    }

    @Test
    void successClearsFailuresAndLock() {
        Administrator locked = new Administrator(fresh.id(), "Admin", fresh.email(), fresh.passwordHash(),
                Administrator.ADMINISTRATOR, 3, NOW);
        Administrator after = LoginPolicy.DEFAULT.afterSuccess(locked);
        assertThat(after.failedLoginCount()).isZero();
        assertThat(after.lockedUntil()).isNull();
    }

    @Test
    void emailsAreNormalised() {
        assertThat(Administrator.normaliseEmail("  Admin@Example.TEST ")).isEqualTo("admin@example.test");
        assertThat(Administrator.normaliseEmail(null)).isEmpty();
    }

    @Test
    void refusesANonsensePolicy() {
        assertThatThrownBy(() -> new LoginPolicy(0, Duration.ofMinutes(1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginPolicy(5, Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
    }
}
