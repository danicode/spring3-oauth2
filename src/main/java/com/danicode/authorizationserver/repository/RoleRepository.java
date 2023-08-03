package com.danicode.authorizationserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.danicode.authorizationserver.entity.Role;
import com.danicode.authorizationserver.enums.RoleName;

public interface RoleRepository extends JpaRepository<Role, Long> {

	Optional<Role> findByRole(RoleName roleName);
}
