package com.auth.jwtdemo.demo.domain;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public JwtAuthenticationToken(String jwt) {
        super(null, JWT.decode(jwt), null);
    }

    public JwtAuthenticationToken(String username, Collection<? extends GrantedAuthority> authorities) {
        super(username, null, authorities);
    }

    @Override
    public DecodedJWT getCredentials() {
        return (DecodedJWT) super.getCredentials();
    }

    @Override
    public String getPrincipal() {
        return (String) super.getPrincipal();
    }
}
