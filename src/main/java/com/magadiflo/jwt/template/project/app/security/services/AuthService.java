package com.magadiflo.jwt.template.project.app.security.services;

import com.magadiflo.jwt.template.project.app.security.dto.LoginRequestDTO;
import com.magadiflo.jwt.template.project.app.security.dto.LoginResponseDTO;
import com.magadiflo.jwt.template.project.app.security.models.SecurityUser;
import com.magadiflo.jwt.template.project.app.security.utility.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    public AuthService(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        Authentication authentication = this.authenticate(loginRequestDTO.username(), loginRequestDTO.password());

        // Si hasta este punto llega y no lanzó ningún error, significa que sí se autenticó correctamente
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();
        return this.loginResponse(securityUser);
    }

    private Authentication authenticate(String username, String password) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return this.authenticationManager.authenticate(authenticationToken);
    }

    @Transactional(readOnly = true)
    private LoginResponseDTO loginResponse(UserDetails userDetails) {
        String username = userDetails.getUsername();
        String accessToken = this.jwtTokenProvider.createAccessToken(userDetails);
        LOG.info("Usuario logueado: {}", username);
        LOG.info("AccessToken: {}", accessToken);
        return new LoginResponseDTO(username, accessToken, "-aún-no-implementado-");
    }
}
