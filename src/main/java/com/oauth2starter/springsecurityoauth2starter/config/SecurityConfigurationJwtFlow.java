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
            // default jwt converter
//           rsc.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter));

            // Configuration with custom jwt converter
            rsc.jwt(jwt -> jwt.jwtAuthenticationConverter(customJwtAuthenticationConvert));
        });
//        http.formLogin(Customizer.withDefaults());
//        http.httpBasic(Customizer.withDefaults());
//        http.oauth2Login(Customizer.withDefaults());
        return http.build();
    }

//    @Bean
//    ClientRegistrationRepository oauth2ClientRegistrationRepository() {
//        ClientRegistration githubClientRegistration = githubClientRegistration();
////        ClientRegistration facebookClientRegistration = facebookClientRegistration();
//        return new InMemoryClientRegistrationRepository(githubClientRegistration);
//    }

//    private ClientRegistration githubClientRegistration() {
//        log.info("Loading Github Client Registration id {}", githubProperties.getClientId());
//        log.info("Loading Github client Registration Secret {}", githubProperties.getClientSecret());
//        return  CommonOAuth2Provider
//                .GITHUB.getBuilder("github")
//                .clientId(githubProperties.getClientId())
//                .clientSecret(githubProperties.getClientSecret())
//                .build();
//    }


//    private ClientRegistration facebookClientRegistration() {
//        return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook")
//                .clientId("")
//                .clientSecret("")
//                .build();
//    }

//    @Bean
//    UserDetailsService userDetailsService() {
//        UserDetails user = User.builder()
//                .username("sagar")
//                .password(passwordEncoder().encode("sagar123"))
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }

//    @Bean
//    PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
}
