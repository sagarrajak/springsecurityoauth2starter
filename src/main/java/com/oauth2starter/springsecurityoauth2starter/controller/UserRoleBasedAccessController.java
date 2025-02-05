package com.oauth2starter.springsecurityoauth2starter.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserRoleBasedAccessController {
    @GetMapping("/myUserPage")
    String getUserRoleBasedAccess(Authentication authentication) {
        return "ROLE_USER ";
    }
}
