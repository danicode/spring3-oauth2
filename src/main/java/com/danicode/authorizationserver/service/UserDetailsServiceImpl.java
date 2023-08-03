package com.danicode.authorizationserver.service;

import lombok.Builder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.danicode.authorizationserver.repository.AppUserRepository;

import lombok.extern.slf4j.Slf4j;

@Service
@Builder
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

	private final AppUserRepository appUserRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return appUserRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
	}
}
