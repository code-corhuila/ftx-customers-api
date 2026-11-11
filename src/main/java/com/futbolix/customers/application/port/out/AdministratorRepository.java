package com.futbolix.customers.application.port.out;

import com.futbolix.customers.domain.Administrator;
import com.futbolix.customers.domain.LoginPolicy;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AdministratorRepository {

    /** The email must already be normalised. */
    Optional<Administrator> findByEmail(String email);

    Optional<Administrator> findById(UUID id);

    /**
     * Counts one failed login atomically (two parallel failures both count) and applies the policy.
     * Returns the account as stored afterwards, or empty if it no longer exists.
     */
    Optional<Administrator> recordFailedLogin(UUID id, Instant now, LoginPolicy policy);

    /** Clears the failure counter and the lock. */
    void recordSuccessfulLogin(UUID id);

    /** Creates the account; false if the email is already taken. */
    boolean insertIfAbsent(Administrator administrator);
}
