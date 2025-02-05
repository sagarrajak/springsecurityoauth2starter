package com.oauth2starter.springsecurityoauth2starter.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
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
@Profile("opacque")
public class SecurityConfigurationOpacFlow {
    @Value("${spring.security.oauth2.resourceserver.opaque-token.introspection-uri}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.resourceserver.opaque-token.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.resourceserver.opaque-token.client-secret}")
    private String clientSecret;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
//                .sessionManagement(session ->
//                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
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
            rsc.opaqueToken(
                    otc -> otc
                            .authenticationConverter(new KeyclockOpacRoleConverter())
                            .introspectionUri(introspectionUri)
                            .introspectionClientCredentials(clientId, clientSecret)
            );
        });
        return http.build();
    }

}
