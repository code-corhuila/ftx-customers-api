package com.futbolix.customers.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.futbolix.customers.adapter.out.security.BcryptSecretHasher;
import com.futbolix.customers.adapter.out.security.InMemoryLoginRateLimiter;
import com.futbolix.customers.adapter.out.security.RsaAccessTokens;
import com.futbolix.customers.adapter.out.security.SecureRandomTokenSecrets;
import com.futbolix.customers.application.port.out.SecurityEventLog.Event;
import com.futbolix.customers.domain.Administrator;
import com.futbolix.customers.domain.LoginPolicy;
import com.futbolix.customers.domain.RefreshToken;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** HU-ADM-002 AC1 and AC3, and the refresh-token rules of security-policy.md. */
class AuthServiceTest {

    /** Made on each run: no fixed credential in the repository. */
    static final String PASSWORD = "pw-" + UUID.randomUUID();
    static final String IP = "10.0.0.7";

    InMemoryStores.Administrators administrators;
    InMemoryStores.RefreshTokens tokens;
    InMemoryStores.Events events;
    InMemoryStores.MutableClock clock;
    BcryptSecretHasher hasher;
    RsaAccessTokens accessTokens;
    AuthService service;
    Administrator alice;
    Administrator bob;

    @BeforeEach
    void setUp() {
        administrators = new InMemoryStores.Administrators();
        tokens = new InMemoryStores.RefreshTokens();
        events = new InMemoryStores.Events();
        clock = new InMemoryStores.MutableClock(Instant.parse("2026-11-11T15:00:00Z"));
        hasher = new BcryptSecretHasher(4);
        accessTokens = new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), "test", "ftx-customers-api");
        service = new AuthService(administrators, tokens, hasher, accessTokens, new SecureRandomTokenSecrets(),
                new InMemoryLoginRateLimiter(10, Duration.ofMinutes(5)), events, LoginPolicy.DEFAULT, clock);
        alice = account("alice@example.test");
        bob = account("bob@example.test");
    }

    Administrator account(String email) {
        Administrator a = new Administrator(UUID.randomUUID(), "Admin " + email, email, hasher.hash(PASSWORD),
                Administrator.ADMINISTRATOR, 0, null);
        administrators.insertIfAbsent(a);
        return a;
    }

    @Test
    void validCredentialsIssueAnAccessTokenAndARefreshToken() {
        AuthResult result = service.login("  Alice@Example.TEST ", PASSWORD, IP);

        assertThat(result.administrator().id()).isEqualTo(alice.id());
        assertThat(result.expiresInSeconds()).isEqualTo(3600);
        assertThat(accessTokens.verify(result.accessToken(), clock.instant()))
                .hasValueSatisfying(a -> assertThat(a.id()).isEqualTo(alice.id()));
        assertThat(result.refreshToken()).matches("[0-9a-f-]{36}\\.[A-Za-z0-9_-]{43}");
        assertThat(tokens.active(alice.id())).isEqualTo(1);
        assertThat(events.recorded).containsExactly(Event.AUTH_LOGIN_SUCCESS);
    }

    @Test
    void theRefreshTokenIsStoredOnlyAsAHash() {
        AuthResult result = service.login("alice@example.test", PASSWORD, IP);
        String secret = result.refreshToken().substring(37);

        RefreshToken stored = tokens.rows.values().iterator().next();
        assertThat(stored.tokenHash()).doesNotContain(secret).startsWith("$2a$");
        assertThat(stored.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofDays(7)));
    }

    @Test
    void wrongPasswordAndUnknownEmailGiveTheSameGenericError() {
        assertThatThrownBy(() -> service.login("alice@example.test", "wrong-password", IP))
                .isInstanceOf(InvalidCredentialsException.class).hasMessage("Invalid email or password");
        assertThatThrownBy(() -> service.login("nobody@example.test", PASSWORD, IP))
                .isInstanceOf(InvalidCredentialsException.class).hasMessage("Invalid email or password");
        assertThat(tokens.rows).isEmpty();
    }

    @Test
    void fiveConsecutiveFailuresLockTheAccountEvenForTheRightPassword() {
        for (int i = 0; i < 5; i++) {
            String address = "10.0.0." + i;
            assertThatThrownBy(() -> service.login("alice@example.test", "wrong-password", address))
                    .isInstanceOf(InvalidCredentialsException.class);
        }
        assertThat(administrators.findById(alice.id()).orElseThrow().isLocked(clock.instant())).isTrue();
        assertThat(events.recorded).contains(Event.AUTH_BRUTE_FORCE_DETECTED);

        assertThatThrownBy(() -> service.login("alice@example.test", PASSWORD, "10.0.0.9"))
                .isInstanceOf(InvalidCredentialsException.class);

        clock.advance(Duration.ofMinutes(15));
        assertThat(service.login("alice@example.test", PASSWORD, "10.0.0.9").administrator().id()).isEqualTo(alice.id());
    }

    @Test
    void aSuccessfulLoginResetsTheFailureCounter() {
        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> service.login("alice@example.test", "wrong-password", IP))
                    .isInstanceOf(InvalidCredentialsException.class);
        }
        service.login("alice@example.test", PASSWORD, IP);
        assertThat(administrators.findById(alice.id()).orElseThrow().failedLoginCount()).isZero();
    }

    @Test
    void lockingOneAdministratorDoesNotLockAnother() {
        for (int i = 0; i < 5; i++) {
            String address = "10.0.1." + i;
            assertThatThrownBy(() -> service.login("alice@example.test", "wrong-password", address))
                    .isInstanceOf(InvalidCredentialsException.class);
        }
        assertThat(service.login("bob@example.test", PASSWORD, "10.0.2.1").administrator().id()).isEqualTo(bob.id());
    }

    @Test
    void theEleventhAttemptFromOneAddressInFiveMinutesIsRateLimited() {
        for (int i = 0; i < 10; i++) {
            assertThatThrownBy(() -> service.login("nobody@example.test", PASSWORD, IP))
                    .isInstanceOf(InvalidCredentialsException.class);
        }
        assertThatThrownBy(() -> service.login("alice@example.test", PASSWORD, IP))
                .isInstanceOf(TooManyLoginAttemptsException.class);
        // Another address is not affected.
        assertThat(service.login("alice@example.test", PASSWORD, "10.9.9.9").administrator().id()).isEqualTo(alice.id());

        clock.advance(Duration.ofMinutes(5));
        assertThat(service.login("alice@example.test", PASSWORD, IP).administrator().id()).isEqualTo(alice.id());
    }

    @Test
    void refreshRotatesTheTokenAndTheOldOneCannotBeUsedAgain() {
        AuthResult login = service.login("alice@example.test", PASSWORD, IP);

        AuthResult refreshed = service.refresh(login.refreshToken(), IP);

        assertThat(refreshed.refreshToken()).isNotEqualTo(login.refreshToken());
        assertThat(refreshed.administrator().id()).isEqualTo(alice.id());
        assertThat(tokens.active(alice.id())).isEqualTo(1);
        assertThatThrownBy(() -> service.refresh(login.refreshToken(), IP))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void reusingASpentTokenRevokesTheWholeFamily() {
        AuthResult login = service.login("alice@example.test", PASSWORD, IP);
        AuthResult refreshed = service.refresh(login.refreshToken(), IP);

        assertThatThrownBy(() -> service.refresh(login.refreshToken(), "203.0.113.5"))
                .isInstanceOf(InvalidRefreshTokenException.class);

        // The legitimate newer token died with its family.
        assertThatThrownBy(() -> service.refresh(refreshed.refreshToken(), IP))
                .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.active(alice.id())).isZero();
        assertThat(events.recorded).contains(Event.AUTH_TOKEN_REVOKED);
    }

    @Test
    void reuseRevokesOnlyThatFamilyNotTheOtherSessionsOfTheSameAdministrator() {
        AuthResult laptop = service.login("alice@example.test", PASSWORD, IP);
        AuthResult phone = service.login("alice@example.test", PASSWORD, IP);
        service.refresh(laptop.refreshToken(), IP);

        assertThatThrownBy(() -> service.refresh(laptop.refreshToken(), IP))
                .isInstanceOf(InvalidRefreshTokenException.class);

        assertThat(service.refresh(phone.refreshToken(), IP).administrator().id()).isEqualTo(alice.id());
    }

    @Test
    void anExpiredRefreshTokenIsRefused() {
        AuthResult login = service.login("alice@example.test", PASSWORD, IP);
        clock.advance(Duration.ofDays(7));
        assertThatThrownBy(() -> service.refresh(login.refreshToken(), IP))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void aTokenWithAWrongSecretIsRefusedAndDoesNotRevokeTheRealOne() {
        AuthResult login = service.login("alice@example.test", PASSWORD, IP);
        String forged = login.refreshToken().substring(0, 37) + "A".repeat(43);

        assertThatThrownBy(() -> service.refresh(forged, IP)).isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(service.refresh(login.refreshToken(), IP).administrator().id()).isEqualTo(alice.id());
    }

    @Test
    void malformedRefreshTokensAreRefused() {
        for (String bad : new String[] {"", "abc", "not-a-uuid.secret", UUID.randomUUID() + ".", UUID.randomUUID() + "." + "x".repeat(129)}) {
            assertThatThrownBy(() -> service.refresh(bad, IP)).isInstanceOf(InvalidRefreshTokenException.class);
        }
    }

    @Test
    void logoutRevokesOnlyTheGivenToken() {
        AuthResult laptop = service.login("alice@example.test", PASSWORD, IP);
        AuthResult phone = service.login("alice@example.test", PASSWORD, IP);

        service.logout(alice.id(), laptop.refreshToken(), false, IP);

        assertThatThrownBy(() -> service.refresh(laptop.refreshToken(), IP)).isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(service.refresh(phone.refreshToken(), IP).administrator().id()).isEqualTo(alice.id());
    }

    @Test
    void logoutOnAllDevicesRevokesEverySessionOfThatAdministratorOnly() {
        service.login("alice@example.test", PASSWORD, IP);
        service.login("alice@example.test", PASSWORD, IP);
        AuthResult bobs = service.login("bob@example.test", PASSWORD, IP);

        service.logout(alice.id(), null, true, IP);

        assertThat(tokens.active(alice.id())).isZero();
        assertThat(service.refresh(bobs.refreshToken(), IP).administrator().id()).isEqualTo(bob.id());
    }

    /** M1: an administrator cannot revoke a session of another administrator. */
    @Test
    void logoutWithTheRefreshTokenOfAnotherAdministratorChangesNothing() {
        AuthResult bobs = service.login("bob@example.test", PASSWORD, IP);
        service.login("alice@example.test", PASSWORD, IP);

        service.logout(alice.id(), bobs.refreshToken(), false, IP);

        assertThat(service.refresh(bobs.refreshToken(), IP).administrator().id()).isEqualTo(bob.id());
        assertThat(tokens.active(alice.id())).isEqualTo(1);
        assertThat(events.recorded).contains(Event.AUTH_UNAUTHORIZED_ACCESS_ATTEMPT);
    }
}
