package com.futbolix.customers.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** security-policy.md, "JWT": RS256, 1 hour, sub/iat/exp/jti/roles, private key never published. */
class RsaAccessTokensTest {

    static final Instant NOW = Instant.parse("2026-11-11T15:00:00Z");
    final RsaAccessTokens tokens = new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), "key-1", "ftx-customers-api");
    final UUID admin = UUID.randomUUID();

    @Test
    void issuesAnRs256TokenWithTheRequiredClaims() throws Exception {
        SignedJWT jwt = SignedJWT.parse(tokens.issue(admin, "ADMINISTRATOR", NOW));

        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("key-1");
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo(admin.toString());
        assertThat(claims.getIssuer()).isEqualTo("ftx-customers-api");
        assertThat(claims.getIssueTime().toInstant()).isEqualTo(NOW);
        assertThat(claims.getExpirationTime().toInstant()).isEqualTo(NOW.plus(Duration.ofHours(1)));
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getStringListClaim("roles")).containsExactly("ADMINISTRATOR");
        // Nothing personal in the payload: only the administrator id.
        assertThat(claims.getClaims().keySet()).containsExactlyInAnyOrder("iss", "sub", "iat", "exp", "jti", "roles");
    }

    @Test
    void verifiesItsOwnTokenUntilItExpires() {
        String token = tokens.issue(admin, "ADMINISTRATOR", NOW);

        assertThat(tokens.verify(token, NOW.plus(Duration.ofMinutes(59)))).hasValueSatisfying(a -> assertThat(a.id()).isEqualTo(admin));
        assertThat(tokens.verify(token, NOW.plus(Duration.ofHours(1)))).isEmpty();
    }

    @Test
    void refusesATamperedToken() {
        String token = tokens.issue(admin, "ADMINISTRATOR", NOW);
        String[] parts = token.split("\\.");
        String otherPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"iss\":\"ftx-customers-api\",\"sub\":\"" + UUID.randomUUID()
                        + "\",\"exp\":9999999999,\"roles\":[\"ADMINISTRATOR\"]}").getBytes());

        assertThat(tokens.verify(parts[0] + "." + otherPayload + "." + parts[2], NOW)).isEmpty();
        assertThat(tokens.verify("not-a-jwt", NOW)).isEmpty();
        assertThat(tokens.verify(null, NOW)).isEmpty();
    }

    @Test
    void refusesATokenSignedByAnotherKeyOrAnotherIssuer() {
        RsaAccessTokens otherKey = new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), "key-1", "ftx-customers-api");
        RsaAccessTokens otherIssuer = new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), "key-1", "someone-else");

        assertThat(tokens.verify(otherKey.issue(admin, "ADMINISTRATOR", NOW), NOW)).isEmpty();
        assertThat(tokens.verify(otherIssuer.issue(admin, "ADMINISTRATOR", NOW), NOW)).isEmpty();
    }

    @Test
    void refusesHs256AndTokensWithoutTheAdministratorRole() throws Exception {
        SignedJWT hs = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("key-1").build(),
                new JWTClaimsSet.Builder().issuer("ftx-customers-api").subject(admin.toString())
                        .expirationTime(Date.from(NOW.plusSeconds(60))).claim("roles", List.of("ADMINISTRATOR")).build());
        hs.sign(new MACSigner(new byte[32]));

        assertThat(tokens.verify(hs.serialize(), NOW)).isEmpty();
        assertThat(tokens.verify(tokens.issue(admin, "CUSTOMER", NOW), NOW)).isEmpty();
    }

    @Test
    void theJwksPublishesThePublicKeyOnly() throws Exception {
        Map<String, Object> json = tokens.publicJwks();
        JWKSet set = JWKSet.parse(json);

        assertThat(set.getKeys()).hasSize(1);
        RSAKey key = (RSAKey) set.getKeys().get(0);
        assertThat(key.isPrivate()).isFalse();
        assertThat(key.getKeyID()).isEqualTo("key-1");
        @SuppressWarnings("unchecked")
        Map<String, Object> published = ((List<Map<String, Object>>) json.get("keys")).get(0);
        // d, p, q, dp, dq and qi are the private parts of an RSA JWK (RFC 7518, section 6.3.2).
        assertThat(published).doesNotContainKeys("d", "p", "q", "dp", "dq", "qi")
                .containsEntry("kty", "RSA").containsEntry("use", "sig").containsEntry("alg", "RS256");
        // A consumer can verify a token with nothing but the JWKS.
        SignedJWT jwt = SignedJWT.parse(tokens.issue(admin, "ADMINISTRATOR", NOW));
        assertThat(jwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(key))).isTrue();
    }

    @Test
    void refusesWeakKeysAndMissingSettings() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        RSAPrivateCrtKey weak = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();

        assertThatThrownBy(() -> new RsaAccessTokens(weak, "k", "i")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new RsaAccessTokens(RsaAccessTokens.ephemeralKey(), " ", "i")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> RsaAccessTokens.parsePkcs8Pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void readsAPkcs8PemKey() {
        RSAPrivateCrtKey key = RsaAccessTokens.ephemeralKey();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";

        assertThat(RsaAccessTokens.parsePkcs8Pem(pem).getModulus()).isEqualTo(key.getModulus());
    }
}
