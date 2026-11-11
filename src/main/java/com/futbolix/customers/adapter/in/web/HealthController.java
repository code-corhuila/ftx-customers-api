package com.futbolix.customers.adapter.in.web;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * GET /api/v1/health with the body of auth-service.yaml. The container probes use the actuator
 * endpoints /health/liveness and /health/readiness instead.
 */
@RestController
public class HealthController {

    private final JdbcClient jdbc;
    private final Clock clock;

    public HealthController(JdbcClient jdbc, Clock clock) {
        this.jdbc = jdbc;
        this.clock = clock;
    }

    @GetMapping("/api/v1/health")
    ResponseEntity<?> health() {
        try {
            jdbc.sql("SELECT 1").query(Integer.class).single();
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new ErrorResponse("SERVICE_UNAVAILABLE", "The service is temporarily unavailable", null, null));
        }
        return ResponseEntity.ok(new Health("ok", Instant.now(clock), Map.of("database", "ok")));
    }

    record Health(String status, Instant timestamp, Map<String, String> dependencies) {
    }
}
