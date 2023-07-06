package com.magadiflo.jwt.template.project.app.security.repositories;

import com.magadiflo.jwt.template.project.app.security.models.entities.RefreshToken;
import com.magadiflo.jwt.template.project.app.security.models.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IRefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findRefreshTokenByToken(String token);

    Optional<RefreshToken> findRefreshTokenByUser(User user);
}
