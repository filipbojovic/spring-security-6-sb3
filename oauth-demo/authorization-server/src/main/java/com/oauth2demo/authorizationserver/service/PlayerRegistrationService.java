package com.oauth2demo.authorizationserver.service;

import com.oauth2demo.authorizationserver.dto.PlayerRegistrationRequest;
import com.oauth2demo.authorizationserver.dto.Role;
import com.oauth2demo.authorizationserver.model.Player;
import com.oauth2demo.authorizationserver.repository.PlayerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PlayerRegistrationService {

    private final PlayerRepository repository;

    public Player playerRegistration(PlayerRegistrationRequest request) {
        var existing = repository.findByEmail(request.getEmail());
        if (existing.isPresent()) {
            throw new DuplicateKeyException("User already exists");
        }

        var toInsert = Player.builder()
                .id(UUID.randomUUID())
                .email(request.getEmail())
                .name(request.getName())
                .password(request.getPassword())
                .role(Role.ADMIN)
                .build();

        return repository.save(toInsert);
    }

}
