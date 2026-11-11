package com.futbolix.customers.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A stored refresh token (security-policy.md, "Refresh Token"): only the BCrypt hash of its secret
 * is kept, it lives 7 days, it can be used once, and every token issued from one login shares the
 * family id, so presenting a spent token can revoke the whole family.
 */
public record RefreshToken(
        UUID id,
        UUID userId,
        UUID familyId,
        String tokenHash,
        Instant createdAt,
        Instant expiresAt,
        Instant usedAt,
        Instant revokedAt) {

    public static final Duration LIFETIME = Duration.ofDays(7);

    public RefreshToken {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(userId, "userId");
        Objects.requireNonNull(familyId, "familyId");
        Objects.requireNonNull(tokenHash, "tokenHash");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public static RefreshToken issue(UUID id, UUID userId, UUID familyId, String tokenHash, Instant now) {
        return new RefreshToken(id, userId, familyId, tokenHash, now, now.plus(LIFETIME), null, null);
    }

    /** Used or revoked: presenting it again is a reuse. */
    public boolean isSpent() {
        return usedAt != null || revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
