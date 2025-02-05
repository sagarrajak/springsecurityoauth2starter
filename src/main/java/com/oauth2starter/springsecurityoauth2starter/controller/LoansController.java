package com.oauth2starter.springsecurityoauth2starter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoansController {
    @GetMapping("/myLoans")
    public String getMyLoans() {
        return  "Get my loans";
    }
}
