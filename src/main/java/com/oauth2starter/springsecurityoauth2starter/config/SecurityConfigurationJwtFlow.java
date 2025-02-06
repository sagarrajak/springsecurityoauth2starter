package com.oauth2starter.springsecurityoauth2starter.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@RequiredArgsConstructor
@Slf4j
@Profile("!opacque")
public class SecurityConfigurationJwtFlow {
//    private final OAuth2ClientProperties githubProperties;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // Default jwt converter
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeyClockRoleConverter());
        // custom jwt converter
        Converter<Jwt, AbstractAuthenticationToken> customJwtAuthenticationConvert = new CustomJwtAuthenticationConvert(new KeyClockRoleConverter());

        http.csrf(AbstractHttpConfigurer::disable)
            .cors(s -> {
                s.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration corsConfiguration = new CorsConfiguration();
                        corsConfiguration.setAllowedOrigins(Collections.singletonList(CorsConfiguration.ALL));
                        corsConfiguration.setAllowedMethods(Arrays.asList("PUT", "DELETE", "POST", "GET"));
                        corsConfiguration.setAllowedHeaders(Collections.singletonList(CorsConfiguration.ALL));
                        corsConfiguration.setAllowCredentials(true);
                        corsConfiguration.setExposedHeaders(Collections.singletonList("Authorization")); // response header
                        corsConfiguration.setMaxAge(3600L);
                        return corsConfiguration;
                    }
                });
            })
            .authorizeHttpRequests(cus -> {
                cus.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                        .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                        .requestMatchers("/myBalance").hasAuthority("VIEWLOANS")
                        .requestMatchers("/myBalance").hasAuthority("VIEWBALANCE")
                        .requestMatchers("/myAdminPage").hasRole("ADMIN")
                        .requestMatchers("/myUserPage").hasRole("USER")
                        .requestMatchers("/myDashboard")
                        .authenticated();
                cus.requestMatchers("/notices", "/contacts", "/error", "/auth/**").permitAll();
            });
        http.oauth2ResourceServer( rsc -> {
            rsc.jwt(jwt -> jwt.jwtAuthenticationConverter(customJwtAuthenticationConvert));
        });
        return http.build();
    }
}
