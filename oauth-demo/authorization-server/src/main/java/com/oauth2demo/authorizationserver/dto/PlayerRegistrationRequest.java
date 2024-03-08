package com.oauth2demo.authorizationserver.dto;

import lombok.Value;

@Value
public class PlayerRegistrationRequest {

    String email;
    String password;
    String name;
    String role;

}
