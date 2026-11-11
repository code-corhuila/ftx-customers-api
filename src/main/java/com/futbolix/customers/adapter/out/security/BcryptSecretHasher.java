package com.futbolix.customers.adapter.out.security;

import com.futbolix.customers.application.port.out.SecretHasher;
import java.security.SecureRandom;
import java.util.HexFormat;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** BCrypt with strength 12 by default (security-rules.md A02: "strength >= 12"). */
public class BcryptSecretHasher implements SecretHasher {

    private final BCryptPasswordEncoder encoder;
    private final String dummyHash;

    public BcryptSecretHasher(int strength) {
        this.encoder = new BCryptPasswordEncoder(strength, new SecureRandom());
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        this.dummyHash = encoder.encode(HexFormat.of().formatHex(random));
    }

    @Override
    public String hash(String secret) {
        return encoder.encode(secret);
    }

    @Override
    public boolean matches(String secret, String hash) {
        if (secret == null || hash == null) {
            return false;
        }
        try {
            return encoder.matches(secret, hash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public void matchAgainstDummy(String secret) {
        encoder.matches(secret == null ? "" : secret, dummyHash);
    }
}
