package com.futbolix.customers.application;

import com.futbolix.customers.application.port.in.Login;
import com.futbolix.customers.application.port.in.Logout;
import com.futbolix.customers.application.port.in.RefreshSession;
import com.futbolix.customers.application.port.out.AccessTokens;
import com.futbolix.customers.application.port.out.AdministratorRepository;
import com.futbolix.customers.application.port.out.LoginRateLimiter;
import com.futbolix.customers.application.port.out.RefreshTokenRepository;
import com.futbolix.customers.application.port.out.SecretHasher;
import com.futbolix.customers.application.port.out.SecurityEventLog;
import com.futbolix.customers.application.port.out.SecurityEventLog.Event;
import com.futbolix.customers.application.port.out.TokenSecrets;
import com.futbolix.customers.domain.Administrator;
import com.futbolix.customers.domain.LoginPolicy;
import com.futbolix.customers.domain.RefreshToken;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Administrator authentication (HU-ADM-002, auth-service.yaml, security-policy.md):
 * login with lockout and per-address rate limit, one-use refresh tokens rotated within a family,
 * reuse detection, and logout.
 */
public class AuthService implements Login, RefreshSession, Logout {

    /** Longest secret part accepted: newSecret() produces 43 characters. */
    private static final int MAX_SECRET_LENGTH = 128;

    private final AdministratorRepository administrators;
    private final RefreshTokenRepository refreshTokens;
    private final SecretHasher hasher;
    private final AccessTokens accessTokens;
    private final TokenSecrets secrets;
    private final LoginRateLimiter rateLimiter;
    private final SecurityEventLog events;
    private final LoginPolicy policy;
    private final Clock clock;

    public AuthService(AdministratorRepository administrators, RefreshTokenRepository refreshTokens,
                       SecretHasher hasher, AccessTokens accessTokens, TokenSecrets secrets,
                       LoginRateLimiter rateLimiter, SecurityEventLog events, LoginPolicy policy, Clock clock) {
        this.administrators = administrators;
        this.refreshTokens = refreshTokens;
        this.hasher = hasher;
        this.accessTokens = accessTokens;
        this.secrets = secrets;
        this.rateLimiter = rateLimiter;
        this.events = events;
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public AuthResult login(String email, String password, String clientAddress) {
        Instant now = clock.instant();
        Optional<Duration> wait = rateLimiter.tryAcquire(clientAddress, now);
        if (wait.isPresent()) {
            events.record(Event.AUTH_BRUTE_FORCE_DETECTED, null, clientAddress, "rate limit per address");
            throw new TooManyLoginAttemptsException(wait.get());
        }

        Optional<Administrator> found = administrators.findByEmail(Administrator.normaliseEmail(email));
        if (found.isEmpty()) {
            hasher.matchAgainstDummy(password);
            events.record(Event.AUTH_LOGIN_FAILURE, null, clientAddress, "unknown account");
            throw new InvalidCredentialsException();
        }

        Administrator account = found.get();
        if (account.isLocked(now)) {
            hasher.matchAgainstDummy(password);
            events.record(Event.AUTH_LOGIN_FAILURE, account.id(), clientAddress, "account locked");
            throw new InvalidCredentialsException();
        }
        if (!account.isAdministrator() || !hasher.matches(password, account.passwordHash())) {
            Optional<Administrator> after = administrators.recordFailedLogin(account.id(), now, policy);
            events.record(Event.AUTH_LOGIN_FAILURE, account.id(), clientAddress, "wrong password");
            if (after.isPresent() && after.get().isLocked(now)) {
                events.record(Event.AUTH_BRUTE_FORCE_DETECTED, account.id(), clientAddress,
                        "account locked after " + policy.maxConsecutiveFailures() + " consecutive failures");
            }
            throw new InvalidCredentialsException();
        }

        administrators.recordSuccessfulLogin(account.id());
        events.record(Event.AUTH_LOGIN_SUCCESS, account.id(), clientAddress, null);
        return issue(policy.afterSuccess(account), UUID.randomUUID(), now);
    }

    @Override
    public AuthResult refresh(String refreshToken, String clientAddress) {
        ParsedToken presented = ParsedToken.parse(refreshToken).orElseThrow(InvalidRefreshTokenException::new);
        RefreshToken stored = refreshTokens.findById(presented.id()).orElseThrow(InvalidRefreshTokenException::new);
        // A wrong secret proves nothing about the owner (it may be a guessed id): leave the family alone.
        if (!hasher.matches(presented.secret(), stored.tokenHash())) {
            throw new InvalidRefreshTokenException();
        }

        Instant now = clock.instant();
        if (stored.isSpent()) {
            revokeFamilyOnReuse(stored, now, clientAddress);
        }
        if (stored.isExpired(now)) {
            throw new InvalidRefreshTokenException();
        }
        if (!refreshTokens.markUsed(stored.id(), now)) {
            // Another request spent it between the read and the update: the same reuse.
            revokeFamilyOnReuse(stored, now, clientAddress);
        }

        Administrator account = administrators.findById(stored.userId())
                .filter(Administrator::isAdministrator)
                .orElseThrow(InvalidRefreshTokenException::new);
        return issue(account, stored.familyId(), now);
    }

    @Override
    public void logout(UUID administratorId, String refreshToken, boolean allDevices, String clientAddress) {
        Instant now = clock.instant();
        if (allDevices || refreshToken == null || refreshToken.isBlank()) {
            int revoked = refreshTokens.revokeAllOf(administratorId, now);
            events.record(Event.AUTH_TOKEN_REVOKED, administratorId, clientAddress, "logout, " + revoked + " token(s)");
            return;
        }
        Optional<ParsedToken> presented = ParsedToken.parse(refreshToken);
        Optional<RefreshToken> stored = presented.flatMap(p -> refreshTokens.findById(p.id()));
        boolean owned = stored.isPresent()
                && stored.get().userId().equals(administratorId)
                && hasher.matches(presented.get().secret(), stored.get().tokenHash());
        if (owned && refreshTokens.revoke(stored.get().id(), administratorId, now)) {
            events.record(Event.AUTH_TOKEN_REVOKED, administratorId, clientAddress, "logout, 1 token(s)");
        } else if (stored.isPresent() && !stored.get().userId().equals(administratorId)) {
            events.record(Event.AUTH_UNAUTHORIZED_ACCESS_ATTEMPT, administratorId, clientAddress,
                    "logout with a refresh token of another administrator");
        }
    }

    private void revokeFamilyOnReuse(RefreshToken stored, Instant now, String clientAddress) {
        int revoked = refreshTokens.revokeFamily(stored.familyId(), now);
        events.record(Event.AUTH_TOKEN_REVOKED, stored.userId(), clientAddress,
                "reuse of a spent refresh token, family revoked, " + revoked + " token(s)");
        throw new InvalidRefreshTokenException();
    }

    private AuthResult issue(Administrator account, UUID familyId, Instant now) {
        String secret = secrets.newSecret();
        UUID tokenId = UUID.randomUUID();
        refreshTokens.insert(RefreshToken.issue(tokenId, account.id(), familyId, hasher.hash(secret), now));
        String accessToken = accessTokens.issue(account.id(), account.role(), now);
        return new AuthResult(accessToken, tokenId + "." + secret, accessTokens.lifetime().toSeconds(), account);
    }

    /** The client form of a refresh token: {@code <id>.<secret>}. */
    record ParsedToken(UUID id, String secret) {

        static Optional<ParsedToken> parse(String raw) {
            if (raw == null) {
                return Optional.empty();
            }
            int dot = raw.indexOf('.');
            if (dot != 36 || raw.length() - dot - 1 < 1 || raw.length() - dot - 1 > MAX_SECRET_LENGTH) {
                return Optional.empty();
            }
            try {
                return Optional.of(new ParsedToken(UUID.fromString(raw.substring(0, dot)), raw.substring(dot + 1)));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }
    }
}
