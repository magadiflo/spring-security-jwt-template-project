package com.magadiflo.jwt.template.project.app.security.services;

import com.magadiflo.jwt.template.project.app.security.dto.LoginRequestDTO;
import com.magadiflo.jwt.template.project.app.security.dto.LoginResponseDTO;
import com.magadiflo.jwt.template.project.app.security.dto.TokenRequestDTO;
import com.magadiflo.jwt.template.project.app.security.exceptions.domain.RefreshTokenException;
import com.magadiflo.jwt.template.project.app.security.models.SecurityUser;
import com.magadiflo.jwt.template.project.app.security.models.entities.RefreshToken;
import com.magadiflo.jwt.template.project.app.security.models.entities.User;
import com.magadiflo.jwt.template.project.app.security.utility.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    public AuthService(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider,
                       RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
    }

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        Authentication authentication = this.authenticate(loginRequestDTO.username(), loginRequestDTO.password());

        // Si hasta este punto llega y no lanzó ningún error, significa que sí se autenticó correctamente
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
        return this.loginResponse(securityUser);
    }

    public LoginResponseDTO renewLogin(TokenRequestDTO tokenRequestDTO) {
        String token = tokenRequestDTO.refreshToken();
        RefreshToken refreshToken = this.refreshTokenService.findRefreshTokenByToken(token)
                .orElseThrow(() -> new RefreshTokenException("RefreshToken no encontrado. Inicie sesión."));

        this.refreshTokenService.verifyExpiration(refreshToken);

        User userDB = refreshToken.getUser();
        String username = userDB.getUsername();
        SecurityUser securityUser = new SecurityUser(userDB);
        String accessToken = this.jwtTokenProvider.createAccessToken(securityUser);

        LOG.info("Usuario renovado: {}", username);
        LOG.info("AccessToken renovado: {}", accessToken);
        LOG.info("RefreshToken actual: {}", token);

        return new LoginResponseDTO(username, accessToken, token);
    }

    private Authentication authenticate(String username, String password) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return this.authenticationManager.authenticate(authenticationToken);
    }

    private LoginResponseDTO loginResponse(SecurityUser securityUser) {
        String username = securityUser.getUsername();
        User user = securityUser.user();

        String accessToken = this.jwtTokenProvider.createAccessToken(securityUser);
        RefreshToken refreshToken = this.refreshTokenService.createRefreshToken(user);

        LOG.info("Usuario logueado: {}", username);
        LOG.info("AccessToken: {}", accessToken);
        LOG.info("RefreshToken: {}", refreshToken.getToken());

        return new LoginResponseDTO(username, accessToken, refreshToken.getToken());
    }
}
