package com.oauth2starter.springsecurityoauth2starter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class BasicController {
    @GetMapping("title")
    String getTitle(Authentication authentication) {
        if (authentication instanceof UsernamePasswordAuthenticationToken authenticationToken) {
            return "Spring Security username password" + authenticationToken.getName();
        }
        if (authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken) {
            return "Spring Security Oauth2 " + oAuth2AuthenticationToken.getName();
        }
        return "Spring Security Oauth2 Starter";
    }
}
