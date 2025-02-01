package com.isasadigzade.security.basic_auth.dto;

import com.isasadigzade.security.basic_auth.model.Role;
import lombok.Builder;

import java.util.Set;

@Builder
public record CreateUserRequest (
        String name,
        String username,
        String password,
        Set<Role> authorities
) {
}
