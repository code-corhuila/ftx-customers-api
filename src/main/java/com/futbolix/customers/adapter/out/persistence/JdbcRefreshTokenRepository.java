package com.futbolix.customers.adapter.out.persistence;

import com.futbolix.customers.application.port.out.RefreshTokenRepository;
import com.futbolix.customers.domain.RefreshToken;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** customers.refresh_token of ftx-customers-db, as customers_app. Rows are revoked, never deleted. */
@Repository
public class JdbcRefreshTokenRepository implements RefreshTokenRepository {

    private final JdbcClient jdbc;

    public JdbcRefreshTokenRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void insert(RefreshToken t) {
        jdbc.sql("""
                        INSERT INTO customers.refresh_token (id, user_id, family_id, token_hash, expires_at, created_at)
                        VALUES (:id, :userId, :familyId, :tokenHash, :expiresAt, :createdAt)""")
                .param("id", t.id())
                .param("userId", t.userId())
                .param("familyId", t.familyId())
                .param("tokenHash", t.tokenHash())
                .param("expiresAt", Timestamp.from(t.expiresAt()))
                .param("createdAt", Timestamp.from(t.createdAt()))
                .update();
    }

    @Override
    public Optional<RefreshToken> findById(UUID id) {
        return jdbc.sql("""
                        SELECT id, user_id, family_id, token_hash, created_at, expires_at, used_at, revoked_at
                          FROM customers.refresh_token WHERE id = :id""")
                .param("id", id)
                .query(JdbcRefreshTokenRepository::map)
                .optional();
    }

    @Override
    public boolean markUsed(UUID id, Instant now) {
        return jdbc.sql("""
                        UPDATE customers.refresh_token SET used_at = :now
                         WHERE id = :id AND used_at IS NULL AND revoked_at IS NULL""")
                .param("now", Timestamp.from(now))
                .param("id", id)
                .update() == 1;
    }

    @Override
    public boolean revoke(UUID id, UUID userId, Instant now) {
        return jdbc.sql("""
                        UPDATE customers.refresh_token SET revoked_at = :now
                         WHERE id = :id AND user_id = :userId AND used_at IS NULL AND revoked_at IS NULL""")
                .param("now", Timestamp.from(now))
                .param("id", id)
                .param("userId", userId)
                .update() == 1;
    }

    @Override
    public int revokeFamily(UUID familyId, Instant now) {
        return jdbc.sql("""
                        UPDATE customers.refresh_token SET revoked_at = :now
                         WHERE family_id = :familyId AND revoked_at IS NULL""")
                .param("now", Timestamp.from(now))
                .param("familyId", familyId)
                .update();
    }

    @Override
    public int revokeAllOf(UUID userId, Instant now) {
        return jdbc.sql("""
                        UPDATE customers.refresh_token SET revoked_at = :now
                         WHERE user_id = :userId AND used_at IS NULL AND revoked_at IS NULL""")
                .param("now", Timestamp.from(now))
                .param("userId", userId)
                .update();
    }

    private static RefreshToken map(ResultSet rs, int row) throws SQLException {
        return new RefreshToken(
                rs.getObject("id", UUID.class),
                rs.getObject("user_id", UUID.class),
                rs.getObject("family_id", UUID.class),
                rs.getString("token_hash"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),
                instant(rs.getTimestamp("used_at")),
                instant(rs.getTimestamp("revoked_at")));
    }

    private static Instant instant(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
