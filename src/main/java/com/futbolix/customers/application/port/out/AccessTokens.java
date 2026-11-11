package com.futbolix.customers.application.port.out;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Issues and checks the RS256 access tokens, and publishes the public keys (JWKS). */
public interface AccessTokens {

    String issue(UUID administratorId, String role, Instant now);

    Duration lifetime();

    /** The administrator of a valid, unexpired token signed by this service; empty otherwise. */
    Optional<AuthenticatedAdministrator> verify(String token, Instant now);

    /** JSON Web Key Set with the public keys only. */
    Map<String, Object> publicJwks();

    record AuthenticatedAdministrator(UUID id, String role) {
    }
}
