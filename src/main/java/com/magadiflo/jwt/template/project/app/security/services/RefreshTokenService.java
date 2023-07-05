package com.magadiflo.jwt.template.project.app.security.services;

import com.magadiflo.jwt.template.project.app.security.models.entities.RefreshToken;
import com.magadiflo.jwt.template.project.app.security.models.entities.User;
import com.magadiflo.jwt.template.project.app.security.repositories.IRefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private static final Logger LOG = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final long EXPIRATION_REFRESH_TOKEN = 5 * 60 * 60 * 1000 + (60 * 1000); //5h 1m
    private final IRefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(IRefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> findRefreshTokenByToken(String token) {
        return this.refreshTokenRepository.findRefreshTokenByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        Long idUser = this.refreshTokenRepository.findRefreshTokenByUser(user)
                .map(RefreshToken::getId)
                .orElseGet(() -> null);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(idUser);
        refreshToken.setUser(user);
        refreshToken.setExpiration(Instant.now().plusMillis(EXPIRATION_REFRESH_TOKEN));
        refreshToken.setToken(UUID.randomUUID().toString());

        return this.refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken refreshToken) {
        if (refreshToken.getExpiration().compareTo(Instant.now()) < 0) {
            this.refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("El refresh token ha expirado. Por favor vuelva a iniciar sesión.");
        }
        return refreshToken;
    }
}
