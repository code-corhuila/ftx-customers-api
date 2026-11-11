package com.futbolix.customers.adapter.out.security;

import com.futbolix.customers.application.port.out.TokenSecrets;
import java.security.SecureRandom;
import java.util.Base64;

/** 256 random bits, Base64 URL without padding (43 characters). */
public class SecureRandomTokenSecrets implements TokenSecrets {

    private final SecureRandom random = new SecureRandom();

    @Override
    public String newSecret() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
