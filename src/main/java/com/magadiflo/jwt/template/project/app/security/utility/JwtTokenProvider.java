package com.magadiflo.jwt.template.project.app.security.utility;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {
    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final long EXPIRATION_TIME = 30 * 60 * 1000; //30min
    private static final String AUTHORITIES = "authorities";
    private static final String ISSUER = "System";
    private static final String AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";
    @Value("${jwt.secret.key}")
    private String jwtSecretKey;

    public String createAccessToken(UserDetails userDetails) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withAudience("User", "Managament", "Portal")
                .withIssuedAt(new Date())
                .withSubject(userDetails.getUsername())
                .withClaim(AUTHORITIES, this.authoritiesToCreateAccessToken(userDetails))
                .withExpiresAt(Instant.now().plusMillis(EXPIRATION_TIME))
                .sign(this.getAlgorithm());
    }

    public boolean isAccessTokenValid(String token) {
        try {
            this.jwtVerifier().verify(token);
            return true;
        } catch (AlgorithmMismatchException e) {
            LOG.error("El algoritmo del encabezado del token no es igual al del JWTVerifier: {}", e.getMessage());
        } catch (SignatureVerificationException e) {
            LOG.error("La firma no es válida: {}", e.getMessage());
        } catch (TokenExpiredException e) {
            LOG.error("El token ha expirado: {}", e.getMessage());
        } catch (MissingClaimException e) {
            LOG.error("Claim faltante: {}", e.getMessage());
        } catch (IncorrectClaimException e) {
            LOG.error("Claim incorrecto: {}", e.getMessage());
        } catch (JWTVerificationException e) {
            LOG.error("Excepción general de verificación de un JWT: {}", e.getMessage());
        }
        return false;
    }

    public String getSubjectFromAccessToken(String token) {
        return this.decodedJWT(token).getSubject();
    }

    public List<GrantedAuthority> getAuthoritiesFromAccessToken(String token) {
        return this.decodedJWT(token).getClaim(AUTHORITIES).asList(String.class).stream()
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    public boolean isBearerToken(HttpServletRequest request) {
        String bearerToken = this.authorizationHeader(request);
        return bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX) && bearerToken.split("\\.").length == 3;
    }

    public String tokenFromRequest(HttpServletRequest request) {
        String bearerToken = this.authorizationHeader(request);
        return bearerToken.substring(TOKEN_PREFIX.length());
    }

    private String authorizationHeader(HttpServletRequest request) {
        return request.getHeader(AUTHORIZATION);
    }

    private JWTVerifier jwtVerifier() {
        return JWT.require(this.getAlgorithm()).build();
    }

    private DecodedJWT decodedJWT(String token) {
        return this.jwtVerifier().verify(token);
    }

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC512(this.jwtSecretKey.getBytes());
    }

    private List<String> authoritiesToCreateAccessToken(UserDetails userDetails) {
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }
}
