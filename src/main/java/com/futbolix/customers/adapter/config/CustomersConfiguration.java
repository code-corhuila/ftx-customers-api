package com.futbolix.customers.adapter.config;

import com.futbolix.customers.adapter.out.security.BcryptSecretHasher;
import com.futbolix.customers.adapter.out.security.InMemoryLoginRateLimiter;
import com.futbolix.customers.adapter.out.security.LoggingSecurityEventLog;
import com.futbolix.customers.adapter.out.security.RsaAccessTokens;
import com.futbolix.customers.adapter.out.security.SecureRandomTokenSecrets;
import com.futbolix.customers.application.AdministratorBootstrap;
import com.futbolix.customers.application.AuthService;
import com.futbolix.customers.application.port.out.AccessTokens;
import com.futbolix.customers.application.port.out.AdministratorRepository;
import com.futbolix.customers.application.port.out.LoginRateLimiter;
import com.futbolix.customers.application.port.out.RefreshTokenRepository;
import com.futbolix.customers.application.port.out.SecretHasher;
import com.futbolix.customers.application.port.out.SecurityEventLog;
import com.futbolix.customers.application.port.out.TokenSecrets;
import com.futbolix.customers.domain.LoginPolicy;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.support.TransactionTemplate;

/** Wires the use cases to their adapters. No framework type reaches the domain or application. */
@Configuration
public class CustomersConfiguration {

    private static final Logger log = LoggerFactory.getLogger(CustomersConfiguration.class);

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    SecretHasher secretHasher(CustomersProperties properties) {
        return new BcryptSecretHasher(properties.security().bcryptStrength());
    }

    @Bean
    AccessTokens accessTokens(CustomersProperties properties) {
        CustomersProperties.Jwt jwt = properties.jwt();
        RSAPrivateCrtKey key;
        if (jwt.privateKey() != null && !jwt.privateKey().isBlank()) {
            key = RsaAccessTokens.parsePkcs8Pem(jwt.privateKey());
        } else if (jwt.ephemeral()) {
            log.warn("CUSTOMERS_JWT_EPHEMERAL=true: signing with a key that lives only in this process. "
                    + "Never use it outside local development and tests.");
            key = RsaAccessTokens.ephemeralKey();
        } else {
            throw new IllegalStateException("Set CUSTOMERS_JWT_PRIVATE_KEY (RSA, PKCS#8 PEM) and CUSTOMERS_JWT_KEY_ID");
        }
        String keyId = jwt.keyId() != null && !jwt.keyId().isBlank() ? jwt.keyId()
                : jwt.ephemeral() ? "ephemeral" : null;
        return new RsaAccessTokens(key, keyId, jwt.issuer());
    }

    @Bean
    LoginRateLimiter loginRateLimiter(CustomersProperties properties) {
        return new InMemoryLoginRateLimiter(properties.security().loginAttemptsPerAddress(),
                properties.security().loginWindow());
    }

    @Bean
    SecurityEventLog securityEventLog() {
        return new LoggingSecurityEventLog();
    }

    @Bean
    TokenSecrets tokenSecrets() {
        return new SecureRandomTokenSecrets();
    }

    @Bean
    LoginPolicy loginPolicy(CustomersProperties properties) {
        return new LoginPolicy(properties.security().maxConsecutiveFailures(), properties.security().lockDuration());
    }

    @Bean
    TransactionalAuthService authService(AdministratorRepository administrators, RefreshTokenRepository refreshTokens,
                            SecretHasher hasher, AccessTokens accessTokens, TokenSecrets secrets,
                            LoginRateLimiter rateLimiter, SecurityEventLog events, LoginPolicy policy,
                            Clock clock, TransactionTemplate transactions) {
        AuthService service = new AuthService(administrators, refreshTokens, hasher, accessTokens, secrets,
                rateLimiter, events, policy, clock);
        return new TransactionalAuthService(service, transactions);
    }

    @Bean
    AdministratorBootstrap administratorBootstrap(AdministratorRepository administrators) {
        return new AdministratorBootstrap(administrators);
    }

    @Bean
    ApplicationRunner bootstrapAdministrator(AdministratorBootstrap bootstrap, CustomersProperties properties) {
        CustomersProperties.Bootstrap b = properties.bootstrap();
        return args -> {
            if (b != null) {
                bootstrap.ensure(b.name(), b.email(), b.passwordHash());
            } else {
                bootstrap.ensure(null, null, null);
            }
        };
    }
}
