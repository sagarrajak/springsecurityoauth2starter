package com.oauth2starter.springsecurityoauth2starter.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;

import java.util.*;
import java.util.stream.Collectors;

public class KeyclockOpacRoleConverter implements OpaqueTokenAuthenticationConverter {
    @Override
    public Authentication convert(
            String introspectedToken,
            OAuth2AuthenticatedPrincipal authenticatedPrincipal
    ) {
        String username = (String)authenticatedPrincipal.getAttribute("preferred_username");
        Map<String, Object> realmAccess = (Map<String, Object>)authenticatedPrincipal.getAttribute("realm_access");
        Objects.requireNonNull(realmAccess, "Realm access required");
        Collection<GrantedAuthority> authorities =
                ((List<String>) realmAccess.getOrDefault("roles", Collections.emptyList()))
                        .stream()
                        .map(role -> "ROLE_"+role)
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }
}
