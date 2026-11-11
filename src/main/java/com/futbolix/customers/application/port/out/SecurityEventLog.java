package com.futbolix.customers.application.port.out;

import java.util.UUID;

/**
 * Security events of 00-governance/security-policy.md ("Audit and security logs"). Records the
 * administrator id and the client address only: never an email, a password or a token.
 */
public interface SecurityEventLog {

    enum Event {
        AUTH_LOGIN_SUCCESS,
        AUTH_LOGIN_FAILURE,
        AUTH_BRUTE_FORCE_DETECTED,
        AUTH_TOKEN_REVOKED,
        AUTH_UNAUTHORIZED_ACCESS_ATTEMPT
    }

    /** {@code administratorId} may be null (unknown email, rate limit). */
    void record(Event event, UUID administratorId, String clientAddress, String reason);
}
