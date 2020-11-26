package com.example.oauthdemo.controller;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/todo")
public class DemoController {
	
	@GetMapping("/")
	@PreAuthorize("#oauth2.hasScope('web-app') or #oauth2.hasScope('rmdb-read-app') or #oauth2.hasScope('rmdb-app') or hasRole('user')")
	Object getTodos() {
		return Arrays.asList("Prepare talk..." + Instant.now());
	}

	
	@GetMapping("/info")
	public Map<String, Object> getUserInfo(@AuthenticationPrincipal Jwt principal) {
	    Map<String, String> map = new Hashtable<String, String>();
	    map.put("user_name", principal.getClaimAsString("preferred_username"));
	    //map.put("organization", principal.getClaimAsString("organization"));
	    return Collections.unmodifiableMap(map);
	}

}
