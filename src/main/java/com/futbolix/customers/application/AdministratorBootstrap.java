package com.futbolix.customers.application;

import com.futbolix.customers.application.port.out.AdministratorRepository;
import com.futbolix.customers.domain.Administrator;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates the first administrator from deployment variables, because no migration may seed a
 * credential. The operator provides a BCrypt hash, never a plain password, so the password is
 * not in any env file either. An existing account is never changed.
 */
public class AdministratorBootstrap {

    private static final Logger log = LoggerFactory.getLogger(AdministratorBootstrap.class);
    /** BCrypt, strength 12 or more (security-rules.md A02). */
    private static final Pattern BCRYPT_12_OR_MORE =
            Pattern.compile("^\\$2[aby]\\$(1[2-9]|[2-3][0-9])\\$[./A-Za-z0-9]{53}$");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final AdministratorRepository administrators;

    public AdministratorBootstrap(AdministratorRepository administrators) {
        this.administrators = administrators;
    }

    /**
     * @return true if an account was created. All three values empty means "do nothing"; some of
     *         them set and others not is a configuration error and stops the start-up.
     */
    public boolean ensure(String fullName, String email, String passwordHash) {
        boolean anySet = notBlank(fullName) || notBlank(email) || notBlank(passwordHash);
        if (!anySet) {
            log.info("No bootstrap administrator configured");
            return false;
        }
        if (!notBlank(fullName) || !notBlank(email) || !notBlank(passwordHash)) {
            throw new IllegalStateException(
                    "Set all of CUSTOMERS_BOOTSTRAP_ADMIN_NAME, CUSTOMERS_BOOTSTRAP_ADMIN_EMAIL and "
                            + "CUSTOMERS_BOOTSTRAP_ADMIN_PASSWORD_HASH, or none of them");
        }
        String normalised = Administrator.normaliseEmail(email);
        if (!EMAIL.matcher(normalised).matches() || normalised.length() > 255) {
            throw new IllegalStateException("CUSTOMERS_BOOTSTRAP_ADMIN_EMAIL is not a valid email");
        }
        if (fullName.strip().length() > 150) {
            throw new IllegalStateException("CUSTOMERS_BOOTSTRAP_ADMIN_NAME is longer than 150 characters");
        }
        if (!BCRYPT_12_OR_MORE.matcher(passwordHash.strip()).matches()) {
            throw new IllegalStateException(
                    "CUSTOMERS_BOOTSTRAP_ADMIN_PASSWORD_HASH must be a BCrypt hash with strength 12 or more");
        }
        Administrator account = new Administrator(UUID.randomUUID(), fullName.strip(), normalised,
                passwordHash.strip(), Administrator.ADMINISTRATOR, 0, null);
        boolean created = administrators.insertIfAbsent(account);
        if (created) {
            log.atInfo().addKeyValue("administratorId", account.id()).log("Bootstrap administrator created");
        } else {
            log.info("Bootstrap administrator already exists: left unchanged");
        }
        return created;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }
}
