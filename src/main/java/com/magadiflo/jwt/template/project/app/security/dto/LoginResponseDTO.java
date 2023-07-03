package com.magadiflo.jwt.template.project.app.security.dto;

public record LoginResponseDTO(String username, String accessToken, String refreshToken) {
}
