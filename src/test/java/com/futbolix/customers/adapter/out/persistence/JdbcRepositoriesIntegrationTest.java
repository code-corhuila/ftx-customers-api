package com.futbolix.customers.adapter.out.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.futbolix.customers.domain.Administrator;
import com.futbolix.customers.domain.LoginPolicy;
import com.futbolix.customers.domain.RefreshToken;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** The JDBC adapters against the real customers schema, connected as customers_app. */
class JdbcRepositoriesIntegrationTest {

    static final String HASH = new BCryptPasswordEncoder(4).encode(UUID.randomUUID().toString());
    static JdbcClient app;
    static JdbcAdministratorRepository administrators;
    static JdbcRefreshTokenRepository tokens;

    Instant now;
    Administrator alice;
    Administrator bob;

    @BeforeAll
    static void database() {
        CustomersDatabase.prepare();
        app = JdbcClient.create(CustomersDatabase.app());
        administrators = new JdbcAdministratorRepository(app);
        tokens = new JdbcRefreshTokenRepository(app);
    }

    @BeforeEach
    void accounts() {
        now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        alice = account("alice-" + UUID.randomUUID() + "@example.test");
        bob = account("bob-" + UUID.randomUUID() + "@example.test");
    }

    Administrator account(String email) {
        Administrator a = new Administrator(UUID.randomUUID(), "Admin", email, HASH, Administrator.ADMINISTRATOR, 0, null);
        assertThat(administrators.insertIfAbsent(a)).isTrue();
        return a;
    }

    RefreshToken token(Administrator owner, UUID family) {
        RefreshToken t = RefreshToken.issue(UUID.randomUUID(), owner.id(), family, HASH, now);
        tokens.insert(t);
        return t;
    }

    @Test
    void storesAndFindsAnAdministratorByNormalisedEmail() {
        assertThat(administrators.findByEmail(alice.email())).hasValueSatisfying(a -> {
            assertThat(a.id()).isEqualTo(alice.id());
            assertThat(a.passwordHash()).isEqualTo(HASH);
            assertThat(a.failedLoginCount()).isZero();
            assertThat(a.lockedUntil()).isNull();
        });
        assertThat(administrators.findById(UUID.randomUUID())).isEmpty();
    }

    @Test
    void insertIfAbsentNeverOverwritesAnExistingEmail() {
        Administrator duplicate = new Administrator(UUID.randomUUID(), "Other", alice.email(),
                new BCryptPasswordEncoder(4).encode("x"), Administrator.ADMINISTRATOR, 0, null);
        assertThat(administrators.insertIfAbsent(duplicate)).isFalse();
        assertThat(administrators.findByEmail(alice.email()).orElseThrow().id()).isEqualTo(alice.id());
    }

    @Test
    void theDatabaseRefusesAPlainPasswordEvenFromTheApplicationUser() {
        Administrator plain = new Administrator(UUID.randomUUID(), "Admin", "plain-" + UUID.randomUUID() + "@example.test",
                "plain-password", Administrator.ADMINISTRATOR, 0, null);
        assertThatThrownBy(() -> administrators.insertIfAbsent(plain)).isInstanceOf(DataAccessException.class);
    }

    @Test
    void failedLoginsLockAtTheFifthExactlyLikeTheDomainPolicy() {
        for (int i = 1; i <= 4; i++) {
            assertThat(administrators.recordFailedLogin(alice.id(), now, LoginPolicy.DEFAULT).orElseThrow().failedLoginCount())
                    .isEqualTo(i);
        }
        Administrator locked = administrators.recordFailedLogin(alice.id(), now, LoginPolicy.DEFAULT).orElseThrow();
        Administrator expected = alice;
        for (int i = 0; i < 5; i++) {
            expected = LoginPolicy.DEFAULT.afterFailure(expected, now);
        }
        assertThat(locked.failedLoginCount()).isEqualTo(expected.failedLoginCount());
        assertThat(locked.lockedUntil()).isEqualTo(expected.lockedUntil());

        administrators.recordSuccessfulLogin(alice.id());
        assertThat(administrators.findById(alice.id()).orElseThrow().lockedUntil()).isNull();
    }

    /** M1: the failures of one administrator never touch another. */
    @Test
    void failuresAreCountedPerAdministrator() {
        administrators.recordFailedLogin(alice.id(), now, LoginPolicy.DEFAULT);
        administrators.recordFailedLogin(alice.id(), now, LoginPolicy.DEFAULT);
        assertThat(administrators.findById(bob.id()).orElseThrow().failedLoginCount()).isZero();
    }

    @Test
    void parallelFailuresAreAllCounted() throws Exception {
        LoginPolicy noLock = new LoginPolicy(1000, Duration.ofMinutes(1));
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Object>> work = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                work.add(() -> administrators.recordFailedLogin(alice.id(), now, noLock));
            }
            pool.invokeAll(work);
        } finally {
            pool.shutdown();
        }
        assertThat(administrators.findById(alice.id()).orElseThrow().failedLoginCount()).isEqualTo(20);
    }

    @Test
    void aRefreshTokenCanBeMarkedUsedOnlyOnce() {
        RefreshToken t = token(alice, UUID.randomUUID());

        assertThat(tokens.markUsed(t.id(), now)).isTrue();
        assertThat(tokens.markUsed(t.id(), now)).isFalse();
        assertThat(tokens.findById(t.id()).orElseThrow().isSpent()).isTrue();
    }

    /** M1: one administrator cannot revoke the token of another. */
    @Test
    void revokeOnlyWorksForTheOwner() {
        RefreshToken bobs = token(bob, UUID.randomUUID());

        assertThat(tokens.revoke(bobs.id(), alice.id(), now)).isFalse();
        assertThat(tokens.findById(bobs.id()).orElseThrow().revokedAt()).isNull();
        assertThat(tokens.revoke(bobs.id(), bob.id(), now)).isTrue();
    }

    /** M1: revoking all of Alice's sessions leaves Bob's alone. */
    @Test
    void revokeAllOfTouchesOnlyThatAdministrator() {
        token(alice, UUID.randomUUID());
        token(alice, UUID.randomUUID());
        RefreshToken bobs = token(bob, UUID.randomUUID());

        assertThat(tokens.revokeAllOf(alice.id(), now)).isEqualTo(2);
        assertThat(tokens.findById(bobs.id()).orElseThrow().isSpent()).isFalse();
    }

    @Test
    void revokeFamilyTouchesOnlyThatFamily() {
        UUID family = UUID.randomUUID();
        RefreshToken first = token(alice, family);
        tokens.markUsed(first.id(), now);
        RefreshToken second = token(alice, family);
        RefreshToken otherSession = token(alice, UUID.randomUUID());

        assertThat(tokens.revokeFamily(family, now)).isEqualTo(2);
        assertThat(tokens.findById(second.id()).orElseThrow().revokedAt()).isNotNull();
        assertThat(tokens.findById(otherSession.id()).orElseThrow().isSpent()).isFalse();
    }

    @Test
    void theApplicationUserCanNeitherDeleteNorChangeTheSchema() {
        assertPermissionDenied(() -> app.sql("DELETE FROM customers.refresh_token").update());
        assertPermissionDenied(() -> app.sql("DELETE FROM customers.user_account").update());
        assertPermissionDenied(() -> app.sql("CREATE TABLE customers.x (id int)").update());
        assertPermissionDenied(() -> app.sql("SELECT count(*) FROM customers.flyway_schema_history").query(Long.class).single());
    }

    /** SQLSTATE 42501 insufficient_privilege, whatever the language of the server messages. */
    static void assertPermissionDenied(org.assertj.core.api.ThrowableAssert.ThrowingCallable call) {
        assertThatThrownBy(call).isInstanceOf(DataAccessException.class)
                .satisfies(e -> assertThat(((DataAccessException) e).getMostSpecificCause())
                        .isInstanceOf(java.sql.SQLException.class)
                        .extracting(c -> ((java.sql.SQLException) c).getSQLState()).isEqualTo("42501"));
    }
}
