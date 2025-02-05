package com.oauth2starter.springsecurityoauth2starter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BalanceController {
    @GetMapping("/myBalance")
    public String getBalance() {
        return "This is balance api";
    }
}
