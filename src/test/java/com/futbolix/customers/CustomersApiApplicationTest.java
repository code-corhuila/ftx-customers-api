package com.futbolix.customers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.futbolix.customers.adapter.out.persistence.CustomersDatabase;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The whole application (configuration, bootstrap, transactions, JDBC adapters, web layer) against
 * the real customers schema, connected as customers_app. The administrator password is made for
 * this run: no credential is fixed in the repository.
 */
@SpringBootTest
@AutoConfigureMockMvc
class CustomersApiApplicationTest {

    static final String PASSWORD = "run-" + UUID.randomUUID();
    static final String EMAIL = "admin-" + UUID.randomUUID() + "@example.test";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    @BeforeAll
    static void database() {
        CustomersDatabase.prepare();
    }

    @DynamicPropertySource
    static void settings(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", CustomersDatabase::url);
        registry.add("spring.datasource.username", () -> "customers_app");
        registry.add("spring.datasource.password", CustomersDatabase::appPassword);
        registry.add("customers.jwt.ephemeral", () -> "true");
        registry.add("customers.security.bcrypt-strength", () -> "4");
        registry.add("customers.bootstrap.name", () -> "Facility Admin");
        registry.add("customers.bootstrap.email", () -> EMAIL.toUpperCase());
        registry.add("customers.bootstrap.password-hash", () -> new BCryptPasswordEncoder(12).encode(PASSWORD));
    }

    JsonNode login(String email, String password, String address) throws Exception {
        String body = mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .with(r -> { r.setRemoteAddr(address); return r; })
                        .content(json.writeValueAsString(new Credentials(email, password))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body);
    }

    JsonNode refresh(String refreshToken, int expectedStatus) throws Exception {
        String body = mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().is(expectedStatus))
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body);
    }

    record Credentials(String email, String password) {
    }

    @Test
    void theBootstrapAdministratorLogsInRefreshesAndLogsOut() throws Exception {
        JsonNode session = login(EMAIL, PASSWORD, "10.1.0.1");
        assertThat(session.path("user").path("email").asText()).isEqualTo(EMAIL);
        assertThat(session.path("expiresIn").asLong()).isEqualTo(3600);

        JsonNode rotated = refresh(session.path("refreshToken").asText(), 200);
        assertThat(rotated.path("refreshToken").asText()).isNotEqualTo(session.path("refreshToken").asText());

        mvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + rotated.path("accessToken").asText()))
                .andExpect(status().isNoContent());
        refresh(rotated.path("refreshToken").asText(), 401);
    }

    @Test
    void reusingASpentRefreshTokenKillsTheNewerOneToo() throws Exception {
        JsonNode session = login(EMAIL, PASSWORD, "10.1.0.2");
        JsonNode rotated = refresh(session.path("refreshToken").asText(), 200);

        JsonNode reuse = refresh(session.path("refreshToken").asText(), 401);
        assertThat(reuse.path("error").asText()).isEqualTo("INVALID_REFRESH_TOKEN");
        refresh(rotated.path("refreshToken").asText(), 401);
    }

    /** M1 over HTTP: Bob's access token cannot end Alice's session. */
    @Test
    void anAdministratorCannotLogOutAnotherOne() throws Exception {
        String bobPassword = "bob-" + UUID.randomUUID();
        String bobEmail = "bob-" + UUID.randomUUID() + "@example.test";
        CustomersDatabase.admin().sql("""
                        INSERT INTO customers.user_account (full_name, email, password_hash)
                        VALUES ('Second Admin', :email, :hash)""")
                .param("email", bobEmail)
                .param("hash", new BCryptPasswordEncoder(4).encode(bobPassword))
                .update();
        JsonNode alice = login(EMAIL, PASSWORD, "10.1.0.3");
        JsonNode bob = login(bobEmail, bobPassword, "10.1.0.4");

        mvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + bob.path("accessToken").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + alice.path("refreshToken").asText() + "\"}"))
                .andExpect(status().isNoContent());

        refresh(alice.path("refreshToken").asText(), 200);
    }

    @Test
    void fiveWrongPasswordsLockTheAccountAndTheCounterSurvivesTheRefusals() throws Exception {
        String email = "lock-" + UUID.randomUUID() + "@example.test";
        String password = "lock-" + UUID.randomUUID();
        CustomersDatabase.admin().sql("""
                        INSERT INTO customers.user_account (full_name, email, password_hash)
                        VALUES ('Lock Admin', :email, :hash)""")
                .param("email", email)
                .param("hash", new BCryptPasswordEncoder(4).encode(password))
                .update();

        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                            .with(r -> { r.setRemoteAddr("10.2.0.1"); return r; })
                            .content(json.writeValueAsString(new Credentials(email, "wrong-password"))))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));
        }
        // The right password is refused with the same generic answer while locked.
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .with(r -> { r.setRemoteAddr("10.2.0.2"); return r; })
                        .content(json.writeValueAsString(new Credentials(email, password))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));

        Object lockedUntil = CustomersDatabase.admin()
                .sql("SELECT locked_until FROM customers.user_account WHERE email = :email")
                .param("email", email).query(Object.class).single();
        assertThat(lockedUntil).isNotNull();
    }

    @Test
    void healthAndJwksAnswerWithoutAuthentication() throws Exception {
        mvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.dependencies.database").value("ok"))
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
        mvc.perform(get("/api/v1/auth/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
        mvc.perform(get("/health/readiness")).andExpect(status().isOk());
    }
}
