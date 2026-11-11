package com.futbolix.customers.application;

import com.futbolix.customers.domain.Administrator;

/** What login and refresh return (AuthResponse of auth-service.yaml). */
public record AuthResult(String accessToken, String refreshToken, long expiresInSeconds, Administrator administrator) {
}
