package com.futbolix.customers.application.port.out;

import com.futbolix.customers.domain.RefreshToken;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository {

    void insert(RefreshToken token);

    Optional<RefreshToken> findById(UUID id);

    /**
     * Marks the token used only if it is still unused and not revoked. False means another request
     * spent it first: the caller treats it as a reuse.
     */
    boolean markUsed(UUID id, Instant now);

    /** Revokes one token of this administrator; false if it is not theirs or already spent. */
    boolean revoke(UUID id, UUID userId, Instant now);

    /** Revokes every active token of the family; returns how many. */
    int revokeFamily(UUID familyId, Instant now);

    /** Revokes every active token of the administrator; returns how many. */
    int revokeAllOf(UUID userId, Instant now);
}
