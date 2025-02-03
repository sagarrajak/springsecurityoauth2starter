package com.oauth2starter.springsecurityoauth2starter.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties("oauth2.client")
@Data
public class OAuth2ClientProperties {
    private String clientId;
    private String clientSecret;
}
