package com.magadiflo.jwt.template.project.app.security.services;

import com.magadiflo.jwt.template.project.app.security.dto.LoginRequestDTO;
import com.magadiflo.jwt.template.project.app.security.dto.LoginResponseDTO;
import com.magadiflo.jwt.template.project.app.security.models.SecurityUser;
import com.magadiflo.jwt.template.project.app.security.models.entities.User;
import com.magadiflo.jwt.template.project.app.security.repositories.UserRepository;
import com.magadiflo.jwt.template.project.app.security.utility.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    public AuthService(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
    }

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        Authentication authentication = this.authenticate(loginRequestDTO.username(), loginRequestDTO.password());

        // Si hasta este punto llega y no lanzó ningún error, significa que sí se autenticó correctamente
        return this.loginResponse(authentication.getName());
    }

    private Authentication authenticate(String username, String password) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return this.authenticationManager.authenticate(authenticationToken);
    }

    @Transactional(readOnly = true)
    private LoginResponseDTO loginResponse(String username) {
        Optional<User> userOptional = this.userRepository.findUserByUsername(username);
        UserDetails userDetails = new SecurityUser(userOptional.orElseThrow());
        String accessToken = this.jwtTokenProvider.createAccessToken(userDetails);
        String refreshToken = this.jwtTokenProvider.createRefreshToken(userDetails);
        LOG.info("Usuario logueado: {}", username);
        LOG.info("AccessToken: {}", accessToken);
        LOG.info("RefreshToken: {}", refreshToken);
        return new LoginResponseDTO(username, accessToken, refreshToken);
    }
}
