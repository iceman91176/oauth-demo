package com.example.oauthdemo.config;

import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

//@Configuration
@EnableWebSecurity(debug = true)
public class MicroserviceSecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final Logger log = LoggerFactory.getLogger(MicroserviceSecurityConfiguration.class);

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    String issuerUri;
    
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic().disable().formLogin(AbstractHttpConfigurer::disable).csrf(AbstractHttpConfigurer::disable)
				.csrf().disable().headers().frameOptions().disable().and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.authorizeRequests(authorize -> authorize
						.mvcMatchers("/messages/**").hasAuthority("SCOPE_message:read")
						.requestMatchers(EndpointRequest.to( //
								InfoEndpoint.class, //
								HealthEndpoint.class //
						)).permitAll() //
						.anyRequest().authenticated())
				//.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.oauth2ResourceServer(
						oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
								.and().jwt().decoder(JwtDecoders.fromIssuerLocation(issuerUri))))
				;
	}

	//@Bean
	public JwtDecoder jwtDecoderByIssuerUri(OAuth2ResourceServerProperties properties) {
		// log.warn("{}",properties.getJwt().getIssuerUri());
		String issuerUri = properties.getJwt().getIssuerUri();
		NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);
		jwtDecoder.setClaimSetConverter(new UsernameSubClaimAdapter());
		// jwtDecoder.setClaimSetConverter(new UsernameSubClaimAdapter());
		return jwtDecoder;
	}

	private JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter("spring-demo-microservice"));
		return jwtAuthenticationConverter;
	}

	class UsernameSubClaimAdapter implements Converter<Map<String, Object>, Map<String, Object>> {

		  private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

		  @Override
		  public Map<String, Object> convert(Map<String, Object> claims) {
		    Map<String, Object> convertedClaims = this.delegate.convert(claims);
		    String username = (String) convertedClaims.get("preferred_username");
		    convertedClaims.put("sub", username);
		    return convertedClaims;
		  }

		}
	
	/*
	 * @Bean JwtDecoder jwtDecoder() { NimbusJwtDecoder jwtDecoder =
	 * NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	 * jwtDecoder.setClaimSetConverter(new CustomJwtAuthenticationConverter(""));
	 * return jwtDecoder; }
	 */
}
