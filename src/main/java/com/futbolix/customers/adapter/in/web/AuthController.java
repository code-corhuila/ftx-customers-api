package com.futbolix.customers.adapter.in.web;

import com.futbolix.customers.adapter.in.web.AuthDtos.AuthResponse;
import com.futbolix.customers.adapter.in.web.AuthDtos.LoginRequest;
import com.futbolix.customers.adapter.in.web.AuthDtos.LogoutRequest;
import com.futbolix.customers.adapter.in.web.AuthDtos.RefreshTokenRequest;
import com.futbolix.customers.application.port.in.Login;
import com.futbolix.customers.application.port.in.Logout;
import com.futbolix.customers.application.port.in.RefreshSession;
import com.futbolix.customers.application.port.out.AccessTokens;
import com.futbolix.customers.application.port.out.AccessTokens.AuthenticatedAdministrator;
import com.futbolix.customers.application.port.out.SecurityEventLog;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.time.Clock;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** /auth/login, /auth/refresh and /auth/logout of auth-service.yaml. */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final String BEARER = "Bearer ";

    private final Login login;
    private final RefreshSession refreshSession;
    private final Logout logout;
    private final AccessTokens accessTokens;
    private final SecurityEventLog events;
    private final Clock clock;

    public AuthController(Login login, RefreshSession refreshSession, Logout logout, AccessTokens accessTokens,
                          SecurityEventLog events, Clock clock) {
        this.login = login;
        this.refreshSession = refreshSession;
        this.logout = logout;
        this.accessTokens = accessTokens;
        this.events = events;
        this.clock = clock;
    }

    @PostMapping("/login")
    ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        return tokens(AuthResponse.of(login.login(body.email(), body.password(), request.getRemoteAddr())));
    }

    @PostMapping("/refresh")
    ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest body, HttpServletRequest request) {
        return tokens(AuthResponse.of(refreshSession.refresh(body.refreshToken(), request.getRemoteAddr())));
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                                @Valid @RequestBody(required = false) LogoutRequest body,
                                HttpServletRequest request) {
        String token = authorization != null && authorization.startsWith(BEARER)
                ? authorization.substring(BEARER.length()).strip() : null;
        AuthenticatedAdministrator administrator = accessTokens.verify(token, clock.instant()).orElseThrow(() -> {
            events.record(SecurityEventLog.Event.AUTH_UNAUTHORIZED_ACCESS_ATTEMPT, null, request.getRemoteAddr(),
                    "logout without a valid access token");
            return new AuthenticationRequiredException();
        });
        String refreshToken = body == null ? null : body.refreshToken();
        boolean allDevices = body != null && Boolean.TRUE.equals(body.allDevices());
        logout.logout(administrator.id(), refreshToken, allDevices, request.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    /** Responses that carry tokens are never cached (RFC 6749, section 5.1). */
    private static ResponseEntity<AuthResponse> tokens(AuthResponse body) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(body);
    }

    /** Missing, invalid or expired access token. */
    public static class AuthenticationRequiredException extends RuntimeException {
    }
}
