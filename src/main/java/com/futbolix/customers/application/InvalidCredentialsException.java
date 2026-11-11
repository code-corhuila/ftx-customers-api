package com.futbolix.customers.application;

/**
 * Wrong email, wrong password or locked account: one generic answer for all three
 * (HU-ADM-002 business rule "Login failures return a generic invalid-credentials response").
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid email or password");
    }
}
