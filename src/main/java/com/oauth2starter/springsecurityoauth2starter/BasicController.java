package com.oauth2starter.springsecurityoauth2starter;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class BasicController {
    @GetMapping("title")
    String getTitle() {
        return "Spring Security Oauth2 Starter";
    }
}
