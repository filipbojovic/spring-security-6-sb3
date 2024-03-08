package com.oauth2demo.authorizationserver.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PlayerRegistrationRequest {

    String email;
    String password;
    String name;
    String role;

}
