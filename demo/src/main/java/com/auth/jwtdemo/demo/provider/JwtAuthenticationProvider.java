package com.auth.jwtdemo.demo.provider;

import com.auth.jwtdemo.demo.domain.JwtAuthenticationToken;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return authenticate((JwtAuthenticationToken) authentication);
    }

    private Authentication authenticate(JwtAuthenticationToken jwtAuthenticationToken) throws AuthenticationException {
        DecodedJWT decodedJWT = jwtAuthenticationToken.getCredentials();
        return new JwtAuthenticationToken(decodedJWT.getSubject(), decodedJWT.getClaim("roles").asList(String.class).stream()
                .map(SimpleGrantedAuthority::new)
                .map(s -> (GrantedAuthority) s)
                .toList());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }


}
