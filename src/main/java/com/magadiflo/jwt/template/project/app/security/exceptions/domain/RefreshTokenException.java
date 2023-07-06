package com.magadiflo.jwt.template.project.app.security.exceptions.domain;

public class RefreshTokenException extends RuntimeException {
    public RefreshTokenException(String message) {
        super(message);
    }
}
