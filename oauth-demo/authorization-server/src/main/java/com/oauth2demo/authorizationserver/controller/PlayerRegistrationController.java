package com.oauth2demo.authorizationserver.controller;

import com.oauth2demo.authorizationserver.dto.PlayerRegistrationRequest;
import com.oauth2demo.authorizationserver.model.Player;
import com.oauth2demo.authorizationserver.service.PlayerRegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/player")
public class PlayerRegistrationController {

    private final PlayerRegistrationService service;

    @PostMapping("/register")
    public ResponseEntity<Player> playerRegistration(@RequestBody PlayerRegistrationRequest request) {
        return ResponseEntity.ok(service.playerRegistration(request));
    }

}
