package com.projects.oauth2.simple.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.projects.oauth2.simple.domain.TokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Controller
public class IndexController {
    @Autowired
    RestTemplate restTemplate;
    @Autowired
    ObjectMapper objectMapper;

    @GetMapping("/index")
    public String index(Model model) {
        String url = "https://accounts.google.com/o/oauth2/auth";
        String clientId = "смотреть в менеджере паролей";
        String scope = "openid email profile";
        String redirectUri = "http://localhost:7999/login/oauth2/code/google";
        String href = String.format("%s?response_type=%s&client_id=%s&scope=%s&redirect_uri=%s",
                url, "code", clientId, scope, redirectUri);
        model.addAttribute("href", href);
        return "index";
    }

    @GetMapping("/login/oauth2/code/google")
    public String response(@RequestParam(value = "code", required = false) String code,
                           @RequestParam(value = "scope", required = false) String scopes,
                           Model model) throws JsonProcessingException {
        String url = "https://www.googleapis.com/oauth2/v4/token";
        String redirectUri = "http://localhost:7999/login/oauth2/code/google";
        HttpHeaders headers = new HttpHeaders();
        String clientId = "смотреть в менеджере паролей";
        String clientSecret = "смотреть в менеджере паролей";
        headers.add("Authorization", "Basic " + Base64.getEncoder().encodeToString(String
                .format("%s:%s", clientId, clientSecret).getBytes()));

        HttpEntity<Map<String, String>> http = new HttpEntity<>(Map.of("code", code, "redirect_uri", redirectUri,
                "grant_type", "authorization_code"), headers);
        ResponseEntity<String> result = restTemplate.exchange(url, HttpMethod.POST, http, String.class);
        TokenResponse tokenResponse = objectMapper.readValue(result.getBody(), TokenResponse.class);
        DecodedJWT jwtToken = JWT.decode(tokenResponse.getIdToken());
        model.addAttribute("name", jwtToken.getClaim("given_name").asString());
        model.addAttribute("email", jwtToken.getClaim("email").asString());
        return "profile";
    }

}
