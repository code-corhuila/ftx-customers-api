package com.futbolix.customers.adapter.in.web;

import com.futbolix.customers.application.port.out.AccessTokens;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** GET /auth/jwks: the public keys other services use to verify the access tokens. */
@RestController
public class KeysController {

    private final AccessTokens accessTokens;

    public KeysController(AccessTokens accessTokens) {
        this.accessTokens = accessTokens;
    }

    @GetMapping("/api/v1/auth/jwks")
    ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(accessTokens.publicJwks());
    }
}
