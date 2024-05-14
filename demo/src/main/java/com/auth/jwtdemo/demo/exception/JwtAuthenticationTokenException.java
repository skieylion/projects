package com.auth.jwtdemo.demo.exception;

public class JwtAuthenticationTokenException extends RuntimeException {
    public JwtAuthenticationTokenException(String msg) {
        super(msg);
    }
}
