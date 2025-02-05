package com.oauth2starter.springsecurityoauth2starter.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeyClockRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        var realmAccess = (Map<String, Object>)source.getClaims().get("realm_access");
        if (realmAccess == null || realmAccess.isEmpty()) {
            return Collections.emptyList();
        }
        Collection<GrantedAuthority> roles = ((List<String>) realmAccess.get("roles"))
                .stream()
                .map(key -> "ROLE_" + key)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return roles;
    }
}
