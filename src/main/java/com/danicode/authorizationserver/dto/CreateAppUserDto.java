package com.danicode.authorizationserver.dto;

import java.util.List;

public record CreateAppUserDto (
	String username,
	String password,
	List<String> roles) {}
