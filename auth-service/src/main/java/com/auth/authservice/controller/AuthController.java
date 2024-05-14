package com.auth.authservice.controller;

import com.auth.authservice.service.JwtGeneratorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "JWT", description = "JWT operations")
public class AuthController {
    private final JwtGeneratorService jwtGeneratorService;

    @PostMapping("/login")
    @Operation(summary = "log in a user")
    public void loginUser(@AuthenticationPrincipal UserDetails userDetails, HttpServletResponse response) {
        jwtGeneratorService.createToken(userDetails, response);
    }
}
