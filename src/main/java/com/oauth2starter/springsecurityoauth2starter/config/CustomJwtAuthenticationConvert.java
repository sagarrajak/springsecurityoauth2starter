package com.oauth2starter.springsecurityoauth2starter.config;

import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

@RequiredArgsConstructor
public class CustomJwtAuthenticationConvert implements Converter<Jwt, AbstractAuthenticationToken> {
    private final KeyClockRoleConverter keyClockRoleConverter;
    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        Collection<GrantedAuthority> authorities = keyClockRoleConverter.convert(source);
        String preferredUsername = source.getClaimAsString("preferred_username");
        if (preferredUsername != null && !preferredUsername.isEmpty()) {
            UserDetails userDetails = User.builder().username(preferredUsername).password("").authorities(authorities).build();
            return new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
        }
        return new UsernamePasswordAuthenticationToken(null, null, authorities);
    }
}
