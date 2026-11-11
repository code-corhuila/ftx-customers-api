package com.futbolix.customers.application;

import com.futbolix.customers.application.port.out.AdministratorRepository;
import com.futbolix.customers.application.port.out.RefreshTokenRepository;
import com.futbolix.customers.application.port.out.SecurityEventLog;
import com.futbolix.customers.domain.Administrator;
import com.futbolix.customers.domain.LoginPolicy;
import com.futbolix.customers.domain.RefreshToken;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory adapters with the same rules as the JDBC ones, for the use-case tests. */
final class InMemoryStores {

    private InMemoryStores() {
    }

    static final class Administrators implements AdministratorRepository {
        final Map<UUID, Administrator> rows = new ConcurrentHashMap<>();

        @Override
        public Optional<Administrator> findByEmail(String email) {
            return rows.values().stream().filter(a -> a.email().equals(email)).findFirst();
        }

        @Override
        public Optional<Administrator> findById(UUID id) {
            return Optional.ofNullable(rows.get(id));
        }

        @Override
        public Optional<Administrator> recordFailedLogin(UUID id, Instant now, LoginPolicy policy) {
            return Optional.ofNullable(rows.computeIfPresent(id, (k, a) -> policy.afterFailure(a, now)));
        }

        @Override
        public void recordSuccessfulLogin(UUID id) {
            rows.computeIfPresent(id, (k, a) -> LoginPolicy.DEFAULT.afterSuccess(a));
        }

        @Override
        public boolean insertIfAbsent(Administrator a) {
            if (findByEmail(a.email()).isPresent()) {
                return false;
            }
            rows.put(a.id(), a);
            return true;
        }
    }

    static final class RefreshTokens implements RefreshTokenRepository {
        final Map<UUID, RefreshToken> rows = new ConcurrentHashMap<>();

        @Override
        public void insert(RefreshToken token) {
            rows.put(token.id(), token);
        }

        @Override
        public Optional<RefreshToken> findById(UUID id) {
            return Optional.ofNullable(rows.get(id));
        }

        @Override
        public boolean markUsed(UUID id, Instant now) {
            RefreshToken t = rows.get(id);
            if (t == null || t.isSpent()) {
                return false;
            }
            rows.put(id, with(t, now, t.revokedAt()));
            return true;
        }

        @Override
        public boolean revoke(UUID id, UUID userId, Instant now) {
            RefreshToken t = rows.get(id);
            if (t == null || t.isSpent() || !t.userId().equals(userId)) {
                return false;
            }
            rows.put(id, with(t, t.usedAt(), now));
            return true;
        }

        @Override
        public int revokeFamily(UUID familyId, Instant now) {
            int n = 0;
            for (RefreshToken t : List.copyOf(rows.values())) {
                if (t.familyId().equals(familyId) && t.revokedAt() == null) {
                    rows.put(t.id(), with(t, t.usedAt(), now));
                    n++;
                }
            }
            return n;
        }

        @Override
        public int revokeAllOf(UUID userId, Instant now) {
            int n = 0;
            for (RefreshToken t : List.copyOf(rows.values())) {
                if (t.userId().equals(userId) && !t.isSpent()) {
                    rows.put(t.id(), with(t, t.usedAt(), now));
                    n++;
                }
            }
            return n;
        }

        long active(UUID userId) {
            return rows.values().stream().filter(t -> t.userId().equals(userId) && !t.isSpent()).count();
        }

        private static RefreshToken with(RefreshToken t, Instant usedAt, Instant revokedAt) {
            return new RefreshToken(t.id(), t.userId(), t.familyId(), t.tokenHash(), t.createdAt(), t.expiresAt(),
                    usedAt, revokedAt);
        }
    }

    static final class Events implements SecurityEventLog {
        final List<Event> recorded = new ArrayList<>();

        @Override
        public synchronized void record(Event event, UUID administratorId, String clientAddress, String reason) {
            recorded.add(event);
        }
    }

    /** A clock the test moves forward. */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
