package com.magadiflo.jwt.template.project.app.security.exceptions;

import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

public record ExceptionHttpResponse(int statusCode, HttpStatus httpStatus, String reasonPhrase, String message,
                                    LocalDateTime timestamp) {
    public ExceptionHttpResponse(int statusCode, HttpStatus httpStatus, String reasonPhrase, String message) {
        this(statusCode, httpStatus, reasonPhrase, message, LocalDateTime.now());
    }
}
