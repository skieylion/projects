package com.auth.authservice.service;

import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import com.auth0.jwt.JWT;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class JwtGeneratorService {

    @Value("${spring.application.name}")
    String serviceName;
    @Value("${app.jwt.access-token-ttl}")
    Integer accessTokenTtl;
    @Value("${app.jwt.refresh-token-ttl}")
    Integer refreshTokenTtl;
    @Value("${app.jwt.secret}")
    String jwtSecret;
    @Value("${app.jwt.cookieName}")
    String cookieName;

    private String generateToken(UserDetails userDetails) {
        int size = userDetails.getAuthorities().size();
        String[] roles = new String[size];
        AtomicInteger inc = new AtomicInteger(0);
        userDetails.getAuthorities().forEach(authority -> roles[inc.getAndIncrement()] = authority.toString());
        return JWT.create()
                .withIssuedAt(Instant.now())
                .withJWTId(UUID.randomUUID().toString())
                .withIssuer(serviceName)
                .withSubject(userDetails.getUsername())
                .withExpiresAt(Instant.now().plusSeconds(accessTokenTtl))
                .withArrayClaim("roles", roles)
                .sign(Algorithm.HMAC256(jwtSecret));
    }

    private Cookie generateRefreshToken(UserDetails userDetails) {
        String refreshToken = JWT.create()
                .withIssuedAt(Instant.now())
                .withJWTId(UUID.randomUUID().toString())
                .withIssuer(serviceName)
                .withSubject(userDetails.getUsername())
                .withExpiresAt(Instant.now().plusSeconds(refreshTokenTtl))
                .sign(Algorithm.HMAC256(jwtSecret));
        Cookie cookie = new Cookie("refresh-token", null);
        cookie.setMaxAge(2 * refreshTokenTtl);
        cookie.setHttpOnly(true);
        cookie.setValue(refreshToken);
        return cookie;
    }

    public void createToken(UserDetails userDetails, HttpServletResponse response) {
        String token = generateToken(userDetails);
        response.setHeader("Authorization", "Bearer " + token);
        response.addCookie(generateRefreshToken(userDetails));
    }

    public static String getClientIp(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }
        return ipAddress;
    }
}
