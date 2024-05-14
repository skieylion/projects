package com.auth.jwtdemo.demo.filter;

import com.auth.jwtdemo.demo.domain.JwtAuthenticationToken;
import com.auth.jwtdemo.demo.domain.JwtBearerAuthenticationToken;
import com.auth.jwtdemo.demo.exception.NotValidJwtAuthenticationTokenException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;
    private final AccessDeniedHandler accessDeniedHandler;
    private final JWTVerifier verifier;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, String secret) {
        this.authenticationManager = authenticationManager;
        this.accessDeniedHandler = new AccessDeniedHandlerImpl();
        this.verifier = JWT.require(Algorithm.HMAC256(secret))
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            JwtAuthenticationToken jwtAuthenticationToken = new JwtBearerAuthenticationToken(request);
            validateJwtAuthenticationToken(jwtAuthenticationToken);
            Authentication authentication = authenticationManager.authenticate(jwtAuthenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            accessDeniedHandler.handle(request, response, new AccessDeniedException("Authentication is failed", e));
        }
    }

    private void validateJwtAuthenticationToken(JwtAuthenticationToken jwtToken) {
        DecodedJWT decodedJWT = jwtToken.getCredentials();
        verifier.verify(decodedJWT);
        Instant expireAt = decodedJWT.getExpiresAtAsInstant();
        if (Instant.now().getEpochSecond() > expireAt.getEpochSecond()) {
            throw new NotValidJwtAuthenticationTokenException();
        }
    }

}
