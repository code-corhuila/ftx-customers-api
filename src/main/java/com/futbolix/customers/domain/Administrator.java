package com.futbolix.customers.domain;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/**
 * An administrator account (06-data/data-dictionary.md, user-service, table users). The only
 * authenticated actor of the MVP: customers have no account (01-context/scope.md, assumption 3).
 */
public record Administrator(
        UUID id,
        String fullName,
        String email,
        String passwordHash,
        String role,
        int failedLoginCount,
        Instant lockedUntil) {

    public static final String ADMINISTRATOR = "ADMINISTRATOR";

    public Administrator {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(email, "email");
        Objects.requireNonNull(passwordHash, "passwordHash");
        Objects.requireNonNull(role, "role");
        if (failedLoginCount < 0) {
            throw new IllegalArgumentException("failedLoginCount must not be negative");
        }
    }

    /** Emails are compared and stored trimmed and in lower case (chk_user_account_email_normalised). */
    public static String normaliseEmail(String raw) {
        return raw == null ? "" : raw.strip().toLowerCase(Locale.ROOT);
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && now.isBefore(lockedUntil);
    }

    public boolean isAdministrator() {
        return ADMINISTRATOR.equals(role);
    }
}
