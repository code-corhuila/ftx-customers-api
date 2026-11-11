package com.futbolix.customers.adapter.out.security;

import com.futbolix.customers.application.port.out.AccessTokens;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * RS256 access tokens (security-policy.md, "JWT"): 1 hour, claims sub, iat, exp, jti and roles,
 * plus iss so a consumer can refuse tokens from anywhere else. The private key never leaves this
 * service; consumers verify with the public keys of GET /auth/jwks.
 */
public class RsaAccessTokens implements AccessTokens {

    public static final Duration LIFETIME = Duration.ofHours(1);
    private static final int MIN_KEY_BITS = 2048;

    private final RSAKey signingKey;
    private final RSASSASigner signer;
    private final RSASSAVerifier verifier;
    private final String issuer;

    public RsaAccessTokens(RSAPrivateCrtKey privateKey, String keyId, String issuer) {
        if (privateKey.getModulus().bitLength() < MIN_KEY_BITS) {
            throw new IllegalStateException("The JWT signing key must have at least " + MIN_KEY_BITS + " bits");
        }
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalStateException("The JWT key id (kid) is required");
        }
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("The JWT issuer is required");
        }
        RSAPublicKey publicKey = publicKeyOf(privateKey);
        this.signingKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
                .keyID(keyId).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
        this.signer = new RSASSASigner(privateKey);
        this.verifier = new RSASSAVerifier(publicKey);
        this.issuer = issuer;
    }

    /** Reads an unencrypted PKCS#8 PEM ("BEGIN PRIVATE KEY"), as written by openssl genpkey. */
    public static RSAPrivateCrtKey parsePkcs8Pem(String pem) {
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return (RSAPrivateCrtKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("The JWT signing key is not an RSA private key in PKCS#8 PEM format");
        }
    }

    /** A key that lives only while the process runs (local development and tests). */
    public static RSAPrivateCrtKey ephemeralKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(MIN_KEY_BITS);
            KeyPair pair = generator.generateKeyPair();
            return (RSAPrivateCrtKey) pair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String issue(UUID administratorId, String role, Instant now) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(administratorId.toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(LIFETIME)))
                .jwtID(UUID.randomUUID().toString())
                .claim("roles", List.of(role))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID()).type(JOSEObjectType.JWT).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not sign the access token", e);
        }
        return jwt.serialize();
    }

    @Override
    public Duration lifetime() {
        return LIFETIME;
    }

    @Override
    public Optional<AuthenticatedAdministrator> verify(String token, Instant now) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())
                    || !signingKey.getKeyID().equals(jwt.getHeader().getKeyID())
                    || !jwt.verify(verifier)) {
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Date expires = claims.getExpirationTime();
            if (!issuer.equals(claims.getIssuer()) || expires == null || !now.isBefore(expires.toInstant())
                    || claims.getSubject() == null) {
                return Optional.empty();
            }
            List<String> roles = claims.getStringListClaim("roles");
            if (roles == null || !roles.contains("ADMINISTRATOR")) {
                return Optional.empty();
            }
            return Optional.of(new AuthenticatedAdministrator(UUID.fromString(claims.getSubject()), "ADMINISTRATOR"));
        } catch (ParseException | JOSEException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    @Override
    public Map<String, Object> publicJwks() {
        return new JWKSet(signingKey.toPublicJWK()).toJSONObject(true);
    }

    private static RSAPublicKey publicKeyOf(RSAPrivateCrtKey privateKey) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
        } catch (Exception e) {
            throw new IllegalStateException("Could not derive the public key", e);
        }
    }
}
