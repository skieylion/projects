package com.auth.jwtdemo.demo.exception;

public class NotValidJwtAuthenticationTokenException extends RuntimeException {
    public NotValidJwtAuthenticationTokenException() {
        super("jwt is not valid");
    }
}
