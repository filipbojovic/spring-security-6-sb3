package com.oauth2demo.authorizationserver.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    ADMIN("ADMIN"),
    PLAYER("PLAYER");

    private final String name;
}
