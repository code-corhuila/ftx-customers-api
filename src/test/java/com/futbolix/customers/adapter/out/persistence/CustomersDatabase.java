package com.futbolix.customers.adapter.out.persistence;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Assumptions;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * A fresh customers schema built by the real migrations of the sibling ftx-customers-db clone
 * (system property customers.db.dir), plus a customers_app user with a password made for this
 * run. Database: FTX_IT_JDBC_URL / FTX_IT_ADMIN_USER / FTX_IT_ADMIN_PASSWORD when set, otherwise
 * a Testcontainers PostgreSQL 16 (CI). Without either, the integration tests are skipped.
 */
public final class CustomersDatabase {

    private static PostgreSQLContainer<?> container;
    private static String url;
    private static String adminUser;
    private static String adminPassword;
    private static String appPassword;

    private CustomersDatabase() {
    }

    public static synchronized void prepare() {
        Path migrations = Path.of(System.getProperty("customers.db.dir", "../ftx-customers-db"));
        Assumptions.assumeTrue(Files.isDirectory(migrations.resolve("01_ddl")),
                "ftx-customers-db not found at " + migrations.toAbsolutePath());
        if (url == null) {
            url = System.getenv("FTX_IT_JDBC_URL");
            adminUser = System.getenv("FTX_IT_ADMIN_USER");
            adminPassword = System.getenv("FTX_IT_ADMIN_PASSWORD");
            if (url == null) {
                Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                        "no FTX_IT_JDBC_URL and no Docker: skipped");
                container = new PostgreSQLContainer<>("postgres:16-alpine").withDatabaseName("ftx");
                container.start();
                url = container.getJdbcUrl();
                adminUser = container.getUsername();
                adminPassword = container.getPassword();
            }
        }

        JdbcClient admin = admin();
        admin.sql("DROP SCHEMA IF EXISTS customers CASCADE").update();
        admin.sql("DROP ROLE IF EXISTS customers_writer").update();
        admin.sql("DROP ROLE IF EXISTS customers_reader").update();
        appPassword = UUID.randomUUID().toString();
        boolean exists = admin.sql("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'customers_app')")
                .query(Boolean.class).single();
        admin.sql((exists ? "ALTER" : "CREATE") + " ROLE customers_app LOGIN PASSWORD '" + appPassword + "'").update();
        admin.sql("SELECT format('GRANT CONNECT ON DATABASE %I TO customers_app', current_database())")
                .query(String.class).optional().ifPresent(grant -> admin.sql(grant).update());

        Flyway.configure()
                .dataSource(url, adminUser, adminPassword)
                .locations("filesystem:" + migrations.resolve("01_ddl"),
                        "filesystem:" + migrations.resolve("02_dml"),
                        "filesystem:" + migrations.resolve("03_dcl"))
                .schemas("customers").defaultSchema("customers")
                .load()
                .migrate();
    }

    public static String url() {
        return url;
    }

    public static String appPassword() {
        return appPassword;
    }

    /** The database administrator: only to arrange data a test needs, never by the code under test. */
    public static JdbcClient admin() {
        return JdbcClient.create(dataSource(adminUser, adminPassword));
    }

    /** customers_app, with exactly the rights ftx-customers-db grants it. */
    public static DataSource app() {
        return dataSource("customers_app", appPassword);
    }

    private static DataSource dataSource(String user, String password) {
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setUrl(url);
        ds.setUser(user);
        ds.setPassword(password);
        return ds;
    }
}
