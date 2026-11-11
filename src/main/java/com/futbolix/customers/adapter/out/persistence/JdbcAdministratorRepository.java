package com.futbolix.customers.adapter.out.persistence;

import com.futbolix.customers.application.port.out.AdministratorRepository;
import com.futbolix.customers.domain.Administrator;
import com.futbolix.customers.domain.LoginPolicy;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** customers.user_account of ftx-customers-db, as customers_app (customers_writer). */
@Repository
public class JdbcAdministratorRepository implements AdministratorRepository {

    private static final String COLUMNS =
            "id, full_name, email, password_hash, role, failed_login_count, locked_until";

    private final JdbcClient jdbc;

    public JdbcAdministratorRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<Administrator> findByEmail(String email) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM customers.user_account WHERE email = :email")
                .param("email", email)
                .query(JdbcAdministratorRepository::map)
                .optional();
    }

    @Override
    public Optional<Administrator> findById(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM customers.user_account WHERE id = :id")
                .param("id", id)
                .query(JdbcAdministratorRepository::map)
                .optional();
    }

    /**
     * One statement, so two failures at the same time both count. Same rule as
     * LoginPolicy.afterFailure: at the limit the counter restarts and the lock starts.
     */
    @Override
    public Optional<Administrator> recordFailedLogin(UUID id, Instant now, LoginPolicy policy) {
        return jdbc.sql("""
                        UPDATE customers.user_account
                           SET locked_until = CASE WHEN failed_login_count + 1 >= :max
                                                   THEN :lockedUntil ELSE locked_until END,
                               failed_login_count = CASE WHEN failed_login_count + 1 >= :max
                                                         THEN 0 ELSE failed_login_count + 1 END
                         WHERE id = :id
                        RETURNING""" + " " + COLUMNS)
                .param("max", policy.maxConsecutiveFailures())
                .param("lockedUntil", Timestamp.from(now.plus(policy.lockDuration())))
                .param("id", id)
                .query(JdbcAdministratorRepository::map)
                .optional();
    }

    @Override
    public void recordSuccessfulLogin(UUID id) {
        jdbc.sql("""
                        UPDATE customers.user_account
                           SET failed_login_count = 0, locked_until = NULL
                         WHERE id = :id AND (failed_login_count <> 0 OR locked_until IS NOT NULL)""")
                .param("id", id)
                .update();
    }

    @Override
    public boolean insertIfAbsent(Administrator a) {
        return jdbc.sql("""
                        INSERT INTO customers.user_account (id, full_name, email, password_hash, role)
                        VALUES (:id, :fullName, :email, :passwordHash, :role)
                        ON CONFLICT (email) DO NOTHING""")
                .param("id", a.id())
                .param("fullName", a.fullName())
                .param("email", a.email())
                .param("passwordHash", a.passwordHash())
                .param("role", a.role())
                .update() == 1;
    }

    private static Administrator map(ResultSet rs, int row) throws SQLException {
        Timestamp locked = rs.getTimestamp("locked_until");
        return new Administrator(
                rs.getObject("id", UUID.class),
                rs.getString("full_name"),
                rs.getString("email"),
                rs.getString("password_hash"),
                rs.getString("role"),
                rs.getInt("failed_login_count"),
                locked == null ? null : locked.toInstant());
    }
}
