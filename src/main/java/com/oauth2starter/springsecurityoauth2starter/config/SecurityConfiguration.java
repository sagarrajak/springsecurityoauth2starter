package com.oauth2starter.springsecurityoauth2starter.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfiguration {
    private final OAuth2ClientProperties githubProperties;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(cus -> {
                cus.requestMatchers("/auth/**").permitAll();
                cus.anyRequest().authenticated();
            });
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.oauth2Login(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    ClientRegistrationRepository oauth2ClientRegistrationRepository() {
        ClientRegistration githubClientRegistration = githubClientRegistration();
//        ClientRegistration facebookClientRegistration = facebookClientRegistration();
        return new InMemoryClientRegistrationRepository(githubClientRegistration);
    }

    private ClientRegistration githubClientRegistration() {
        log.info("Loading Github Client Registration id {}", githubProperties.getClientId());
        log.info("Loading Github client Registration Secret {}", githubProperties.getClientSecret());
        return  CommonOAuth2Provider
                .GITHUB.getBuilder("github")
                .clientId(githubProperties.getClientId())
                .clientSecret(githubProperties.getClientSecret())
                .build();
    }

//    private ClientRegistration facebookClientRegistration() {
//        return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook")
//                .clientId("")
//                .clientSecret("")
//                .build();
//    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("sagar")
                .password(passwordEncoder().encode("sagar123"))
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
