package com.futbolix.customers.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.futbolix.customers.domain.Administrator;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** No migration seeds a credential: the first administrator comes from deployment variables. */
class AdministratorBootstrapTest {

    final InMemoryStores.Administrators administrators = new InMemoryStores.Administrators();
    final AdministratorBootstrap bootstrap = new AdministratorBootstrap(administrators);
    /** Generated per run: no fixed credential in the repository. */
    final String hash12 = new BCryptPasswordEncoder(12).encode(java.util.UUID.randomUUID().toString());

    @Test
    void createsTheFirstAdministratorWithANormalisedEmail() {
        assertThat(bootstrap.ensure("Facility Admin", " Admin@Example.TEST ", hash12)).isTrue();

        Administrator created = administrators.findByEmail("admin@example.test").orElseThrow();
        assertThat(created.role()).isEqualTo("ADMINISTRATOR");
        assertThat(created.passwordHash()).isEqualTo(hash12);
    }

    @Test
    void neverChangesAnExistingAccount() {
        bootstrap.ensure("Facility Admin", "admin@example.test", hash12);
        String other = new BCryptPasswordEncoder(12).encode(java.util.UUID.randomUUID().toString());

        assertThat(bootstrap.ensure("Someone Else", "admin@example.test", other)).isFalse();
        assertThat(administrators.findByEmail("admin@example.test").orElseThrow().passwordHash()).isEqualTo(hash12);
    }

    @Test
    void nothingConfiguredMeansNothingCreated() {
        assertThat(bootstrap.ensure(null, "", " ")).isFalse();
        assertThat(administrators.rows).isEmpty();
    }

    @Test
    void refusesHalfConfigurationPlainPasswordsAndWeakHashes() {
        assertThatThrownBy(() -> bootstrap.ensure("Facility Admin", "admin@example.test", null))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> bootstrap.ensure("Facility Admin", "admin@example.test", "a-plain-password"))
                .isInstanceOf(IllegalStateException.class);
        String weak = new BCryptPasswordEncoder(4).encode("x");
        assertThatThrownBy(() -> bootstrap.ensure("Facility Admin", "admin@example.test", weak))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("strength 12");
        assertThatThrownBy(() -> bootstrap.ensure("Facility Admin", "not-an-email", hash12))
                .isInstanceOf(IllegalStateException.class);
        assertThat(administrators.rows).isEmpty();
    }
}
