package com.oauth2starter.springsecurityoauth2starter.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@Slf4j
@Profile("social")
public class SecurityConfigSocialLogin {
    private final OAuth2ClientProperties githubProperties;

    public SecurityConfigSocialLogin(OAuth2ClientProperties oauth2ClientProperties) {
        this.githubProperties = oauth2ClientProperties;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
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
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")))
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
