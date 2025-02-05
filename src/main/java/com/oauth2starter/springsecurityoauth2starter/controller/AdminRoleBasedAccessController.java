package com.oauth2starter.springsecurityoauth2starter.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminRoleBasedAccessController {
    @GetMapping("/myAdminPage")
    String getAdminRoleBasedAccess() {
        return "USER_ADMIN_PAGE";
    }
}
