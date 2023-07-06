package com.magadiflo.jwt.template.project.app.security.exceptions;

import com.magadiflo.jwt.template.project.app.security.exceptions.domain.RefreshTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private final static Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<ExceptionHttpResponse> refreshTokenException(RefreshTokenException e) {
        LOG.error(e.getMessage());
        return this.createExceptionHttpResponse(HttpStatus.UNAUTHORIZED, e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ExceptionHttpResponse> internalServerErrorException(Exception e) {
        LOG.error(e.getMessage());
        return this.createExceptionHttpResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Error general");
    }

    private ResponseEntity<ExceptionHttpResponse> createExceptionHttpResponse(HttpStatus httpStatus, String message) {
        ExceptionHttpResponse body = new ExceptionHttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase(), message);
        return ResponseEntity.status(httpStatus).body(body);
    }

}
