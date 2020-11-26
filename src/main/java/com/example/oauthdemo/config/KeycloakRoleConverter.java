package com.example.oauthdemo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());

	private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

	private final String resourceId;


	public KeycloakRoleConverter(String resourceId) {
		this.resourceId = resourceId;
	}

	private static Collection<? extends GrantedAuthority> extractResourceRoles(final Jwt jwt, final String resourceId) {
		Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
		Map<String, Object> resource;
		Collection<String> resourceRoles;
		if (resourceAccess != null && (resource = (Map<String, Object>) resourceAccess.get(resourceId)) != null
				&& (resourceRoles = (Collection<String>) resource.get("roles")) != null)
			return resourceRoles.stream().map(x -> new SimpleGrantedAuthority("ROLE_" + x)).collect(Collectors.toSet());
		return Collections.emptySet();
	}


	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		// TODO Auto-generated method stub
		
		Collection<GrantedAuthority> authorities = Stream
				.concat(defaultGrantedAuthoritiesConverter.convert(jwt).stream(),
						extractResourceRoles(jwt, resourceId).stream())
				.collect(Collectors.toSet());
		
		return authorities;
		
		/*
		final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
        return ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> "ROLE_" + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
		*/
		
		//return null;
	}

}
