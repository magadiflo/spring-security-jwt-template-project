package com.magadiflo.jwt.template.project.app.security.controllers;

import com.magadiflo.jwt.template.project.app.security.dto.LoginRequestDTO;
import com.magadiflo.jwt.template.project.app.security.dto.LoginResponseDTO;
import com.magadiflo.jwt.template.project.app.security.dto.TokenRequestDTO;
import com.magadiflo.jwt.template.project.app.security.services.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(path = "/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        return ResponseEntity.ok(this.authService.login(loginRequestDTO));
    }

    @PostMapping(path = "/refresh-token")
    public ResponseEntity<LoginResponseDTO> refreshToken(@RequestBody TokenRequestDTO tokenRequestDTO) {
        return ResponseEntity.ok(this.authService.renewLogin(tokenRequestDTO));
    }
}
