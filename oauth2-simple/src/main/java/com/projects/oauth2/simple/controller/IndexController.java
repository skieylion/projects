package com.projects.oauth2.simple.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public class IndexController {
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
    public String response(@RequestParam("code") String code, @RequestParam("scope") String scopes, Model model) {
        model.addAttribute("code", code);
        model.addAttribute("scopes", scopes);
        return "profile";
    }

}
