package com.danicode.authorizationserver.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.danicode.authorizationserver.dto.CreateAppUserDto;
import com.danicode.authorizationserver.dto.MessageDto;
import com.danicode.authorizationserver.entity.AppUser;
import com.danicode.authorizationserver.entity.Role;
import com.danicode.authorizationserver.enums.RoleName;
import com.danicode.authorizationserver.repository.AppUserRepository;
import com.danicode.authorizationserver.repository.RoleRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {

	private final AppUserRepository appUserRepository;
	private final RoleRepository repository;
	private final PasswordEncoder passwordEncoder;
	
	public MessageDto createUser(CreateAppUserDto dto) {
		AppUser appUser = AppUser.builder()
                .username(dto.username())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = repository.findByRole(RoleName.valueOf(r))
                    .orElseThrow(()-> new RuntimeException("role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepository.save(appUser);
        return new MessageDto("user " + appUser.getUsername() + " saved");
	}
}
