package com.futbolix.customers.application;

import java.time.Duration;

/** More than 10 login attempts from one address in 5 minutes (security-rules.md A07). */
public class TooManyLoginAttemptsException extends RuntimeException {

    private final Duration retryAfter;

    public TooManyLoginAttemptsException(Duration retryAfter) {
        super("Too many requests, try again later");
        this.retryAfter = retryAfter;
    }

    public Duration retryAfter() {
        return retryAfter;
    }
}
