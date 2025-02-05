package com.oauth2starter.springsecurityoauth2starter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {
    @GetMapping("/contacts")
    public String getMyContactDetails() {
        return "THis is authenticated";
    }
}
