package com.oauth2demo.authorizationserver.service;

import com.oauth2demo.authorizationserver.dto.PlayerRegistrationRequest;
import com.oauth2demo.authorizationserver.dto.Role;
import com.oauth2demo.authorizationserver.model.Player;
import com.oauth2demo.authorizationserver.repository.PlayerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PlayerRegistrationService {

    private final PlayerRepository repository;

    public Player playerRegistration(PlayerRegistrationRequest request) {
        var toInsert = Player.builder()
                .id(UUID.randomUUID())
                .email(request.getEmail())
                .name(request.getName())
                .password(request.getPassword())
                .role(Role.valueOf(request.getRole()))
                .build();

        return repository.save(toInsert);
    }

}
