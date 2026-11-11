package com.futbolix.customers.application.port.out;

/** Unguessable secrets for refresh tokens (SecureRandom, security-rules.md A02). */
public interface TokenSecrets {

    String newSecret();
}
