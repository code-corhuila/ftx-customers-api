package com.futbolix.customers.adapter.in.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.futbolix.customers.adapter.out.security.RsaAccessTokens;
import com.futbolix.customers.application.AuthResult;
import com.futbolix.customers.application.InvalidCredentialsException;
import com.futbolix.customers.application.InvalidRefreshTokenException;
import com.futbolix.customers.application.TooManyLoginAttemptsException;
import com.futbolix.customers.application.port.in.Login;
import com.futbolix.customers.application.port.in.Logout;
import com.futbolix.customers.application.port.in.RefreshSession;
import com.futbolix.customers.application.port.out.AccessTokens;
import com.futbolix.customers.application.port.out.SecurityEventLog;
import com.futbolix.customers.domain.Administrator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/** The HTTP contract of auth-service.yaml: paths, status codes, bodies and headers. */
@WebMvcTest(controllers = {AuthController.class, KeysController.class})
class AuthControllerTest {

    static final Instant NOW = Instant.parse("2026-11-11T15:00:00Z");
    static final RsaAccessTokens TOKENS = new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), "key-1", "ftx-customers-api");
    static final UUID ADMIN = UUID.randomUUID();

    @TestConfiguration
    static class Beans {
        @Bean
        AccessTokens accessTokens() {
            return TOKENS;
        }

        @Bean
        Clock clock() {
            return Clock.fixed(NOW, ZoneOffset.UTC);
        }
    }

    @Autowired MockMvc mvc;
    @MockitoBean Login login;
    @MockitoBean RefreshSession refreshSession;
    @MockitoBean Logout logout;
    @MockitoBean SecurityEventLog events;
    @MockitoBean JdbcClient jdbc;

    AuthResult result() {
        Administrator admin = new Administrator(ADMIN, "Facility Admin", "admin@example.test",
                "$2a$12$" + "a".repeat(53), "ADMINISTRATOR", 0, null);
        return new AuthResult("access.jwt.value", UUID.randomUUID() + ".secret", 3600, admin);
    }

    @Test
    void loginAnswersTheAuthResponseAndIsNeverCached() throws Exception {
        given(login.login(eq("admin@example.test"), eq("long-enough-password"), anyString())).willReturn(result());

        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin@example.test\",\"password\":\"long-enough-password\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.accessToken").value("access.jwt.value"))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andExpect(jsonPath("$.user.id").value(ADMIN.toString()))
                .andExpect(jsonPath("$.user.email").value("admin@example.test"))
                .andExpect(jsonPath("$.user.role").value("ADMINISTRATOR"))
                // Only id, email and role: never the name, phone, hash or lock fields.
                .andExpect(jsonPath("$.user.fullName").doesNotExist())
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist());
    }

    @Test
    void invalidCredentialsAre401WithTheContractCode() throws Exception {
        given(login.login(anyString(), anyString(), anyString())).willThrow(new InvalidCredentialsException());

        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin@example.test\",\"password\":\"wrong-password\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("Invalid email or password"))
                .andExpect(jsonPath("$.traceId").isNotEmpty());
    }

    @Test
    void invalidBodiesAre400AndNeverEchoTheValues() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"MySecretPass1\",\"password\":\"short\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details[?(@.field=='email')]").exists())
                .andExpect(jsonPath("$.details[?(@.field=='password')]").exists())
                .andExpect(content().string(not(containsString("MySecretPass1"))));

        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin@example.test\",\"password\":\"long-enough-password\",\"role\":\"ADMINISTRATOR\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("role"));

        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.TEXT_PLAIN).content("x"))
                .andExpect(status().isUnsupportedMediaType());
        verify(login, never()).login(anyString(), anyString(), anyString());
    }

    @Test
    void rateLimitIs429WithRetryAfter() throws Exception {
        given(login.login(anyString(), anyString(), anyString()))
                .willThrow(new TooManyLoginAttemptsException(Duration.ofMillis(120_500)));

        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"admin@example.test\",\"password\":\"long-enough-password\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "121"))
                .andExpect(jsonPath("$.error").value("TOO_MANY_REQUESTS"));
    }

    @Test
    void refreshAnswersNewTokensOr401() throws Exception {
        given(refreshSession.refresh(eq("good"), anyString())).willReturn(result());
        given(refreshSession.refresh(eq("spent"), anyString())).willThrow(new InvalidRefreshTokenException());

        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content("{\"refreshToken\":\"good\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content("{\"refreshToken\":\"spent\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_REFRESH_TOKEN"));
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void logoutNeedsAValidAccessTokenAndAnswers204() throws Exception {
        String bearer = "Bearer " + TOKENS.issue(ADMIN, "ADMINISTRATOR", NOW);

        mvc.perform(post("/api/v1/auth/logout").header("Authorization", bearer).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"r\",\"allDevices\":false}"))
                .andExpect(status().isNoContent());
        verify(logout).logout(eq(ADMIN), eq("r"), eq(false), anyString());

        mvc.perform(post("/api/v1/auth/logout").header("Authorization", bearer))
                .andExpect(status().isNoContent());
        verify(logout).logout(eq(ADMIN), isNull(), eq(false), anyString());
    }

    @Test
    void logoutWithoutOrWithABadOrExpiredTokenIs401() throws Exception {
        String expired = TOKENS.issue(ADMIN, "ADMINISTRATOR", NOW.minus(Duration.ofHours(2)));
        String foreign = new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), "key-1", "ftx-customers-api")
                .issue(ADMIN, "ADMINISTRATOR", NOW);

        for (String authorization : new String[] {null, "Bearer ", "Bearer " + expired, "Bearer " + foreign, "Basic abc"}) {
            var request = post("/api/v1/auth/logout");
            if (authorization != null) {
                request = request.header("Authorization", authorization);
            }
            mvc.perform(request)
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string("WWW-Authenticate", "Bearer"))
                    .andExpect(jsonPath("$.error").value("UNAUTHORIZED"));
        }
        verify(logout, never()).logout(any(), any(), anyBoolean(), any());
    }

    @Test
    void jwksIsPublicAndCacheable() throws Exception {
        mvc.perform(get("/api/v1/auth/jwks"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "max-age=300, public"))
                .andExpect(jsonPath("$.keys[0].kid").value("key-1"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
    }

    @Test
    void unknownPathsAndMethodsUseTheErrorFormat() throws Exception {
        mvc.perform(get("/api/v1/auth/login")).andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("METHOD_NOT_ALLOWED"));
        mvc.perform(get("/api/v1/nothing")).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("NOT_FOUND"));
    }
}
