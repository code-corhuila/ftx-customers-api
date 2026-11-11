package com.futbolix.customers.application;

/** Unknown, wrong, expired, used or revoked refresh token: one answer for all of them. */
public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("The refresh token is invalid or expired");
    }
}
