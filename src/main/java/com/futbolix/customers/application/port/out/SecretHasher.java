package com.futbolix.customers.application.port.out;

/** One-way hashing of passwords and refresh-token secrets (BCrypt, security-rules.md A02). */
public interface SecretHasher {

    String hash(String secret);

    boolean matches(String secret, String hash);

    /**
     * Spends the same time as a real comparison, so an unknown email answers as slowly as a
     * wrong password and the response time does not reveal which emails exist.
     */
    void matchAgainstDummy(String secret);
}
