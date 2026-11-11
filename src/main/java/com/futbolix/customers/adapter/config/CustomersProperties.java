package com.futbolix.customers.adapter.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Settings under "customers" in application.yml; each one comes from an environment variable. */
@ConfigurationProperties("customers")
public record CustomersProperties(Jwt jwt, Security security, Bootstrap bootstrap) {

    /**
     * @param privateKey RSA private key, PKCS#8 PEM. Never versioned.
     * @param keyId      kid published in the JWKS and written in every token header.
     * @param issuer     iss claim.
     * @param ephemeral  true only for local development and tests: a new key on every start, so
     *                   every token dies with the process. Ignored when privateKey is set.
     */
    public record Jwt(String privateKey, String keyId, @DefaultValue("ftx-customers-api") String issuer,
                      @DefaultValue("false") boolean ephemeral) {
    }

    /**
     * @param bcryptStrength        12 or more outside tests (security-rules.md A02).
     * @param loginAttemptsPerAddress attempts allowed per address in {@code loginWindow}.
     */
    public record Security(@DefaultValue("12") int bcryptStrength,
                           @DefaultValue("10") int loginAttemptsPerAddress,
                           @DefaultValue("5m") Duration loginWindow,
                           @DefaultValue("5") int maxConsecutiveFailures,
                           @DefaultValue("15m") Duration lockDuration) {
    }

    /** First administrator; all three or none (AdministratorBootstrap). */
    public record Bootstrap(String name, String email, String passwordHash) {
    }
}
