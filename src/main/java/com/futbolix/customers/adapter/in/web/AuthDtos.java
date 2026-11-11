package com.futbolix.customers.adapter.in.web;

import com.futbolix.customers.application.AuthResult;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.UUID;

/** Request and response bodies of auth-service.yaml. */
final class AuthDtos {

    private AuthDtos() {
    }

    /** LoginRequest. The password is never logged nor echoed back. */
    record LoginRequest(
            @NotBlank @Email @Size(max = 255) String email,
            @NotNull @Size(min = 8, max = 100) String password) {

        @Override
        public String toString() {
            return "LoginRequest[email=<hidden>, password=<hidden>]";
        }
    }

    /** RefreshTokenRequest. */
    record RefreshTokenRequest(@NotBlank @Size(max = 200) String refreshToken) {

        @Override
        public String toString() {
            return "RefreshTokenRequest[refreshToken=<hidden>]";
        }
    }

    /** LogoutRequest: both fields optional. */
    record LogoutRequest(@Size(max = 200) String refreshToken, Boolean allDevices) {

        @Override
        public String toString() {
            return "LogoutRequest[refreshToken=<hidden>, allDevices=" + allDevices + "]";
        }
    }

    /** AuthResponse. */
    record AuthResponse(String accessToken, String refreshToken, long expiresIn, AdministratorSummary user) {

        static AuthResponse of(AuthResult result) {
            return new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresInSeconds(),
                    new AdministratorSummary(result.administrator().id(), result.administrator().email(),
                            result.administrator().role()));
        }
    }

    /** AdministratorSummary: id, email and role only, never the name, phone or hash. */
    record AdministratorSummary(UUID id, String email, String role) {
    }
}
