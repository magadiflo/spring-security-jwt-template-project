package com.magadiflo.jwt.template.project.app.security.services;

import com.magadiflo.jwt.template.project.app.security.dto.LoginRequestDTO;
import com.magadiflo.jwt.template.project.app.security.dto.LoginResponseDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        LOG.info("Logueando al usuario: {}", loginRequestDTO);

        // TODO authenticar al usuario

        return new LoginResponseDTO("test", "12345", "abcd");
    }

}
