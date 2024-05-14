package com.auth.jwtdemo.demo.domain;

import com.auth.jwtdemo.demo.exception.JwtAuthenticationTokenException;
import jakarta.servlet.http.HttpServletRequest;

public class JwtBearerAuthenticationToken extends JwtAuthenticationToken {
    public JwtBearerAuthenticationToken(HttpServletRequest request) {
        super(extractJwtFromRequest(request));
        setAuthenticated(false);
    }

    private static String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        throw new JwtAuthenticationTokenException("JWT Bearer is not correct");
    }
}
