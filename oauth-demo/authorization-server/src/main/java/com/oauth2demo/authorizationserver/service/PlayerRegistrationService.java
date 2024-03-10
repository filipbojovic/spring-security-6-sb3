package com.oauth2demo.authorizationserver.service;

import com.oauth2demo.authorizationserver.dto.PlayerRegistrationRequest;
import com.oauth2demo.authorizationserver.dto.Role;
import com.oauth2demo.authorizationserver.model.Player;
import com.oauth2demo.authorizationserver.model.UserAuthority;
import com.oauth2demo.authorizationserver.repository.PlayerRepository;
import com.oauth2demo.authorizationserver.repository.UserAuthorityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PlayerRegistrationService {

    private final PlayerRepository        repository;
    private final UserAuthorityRepository userAuthorityRepository;

    public Player playerRegistration(PlayerRegistrationRequest request) {
        var existing = repository.findByEmail(request.getEmail());
        if (existing.isPresent()) {
            throw new DuplicateKeyException("User already exists");
        }
        var playerId = UUID.randomUUID();
        var authorities = getAuthorities(playerId);

        var toInsert = Player.builder()
                .id(playerId)
                .email(request.getEmail())
                .name(request.getName())
                .password(request.getPassword())
                .authorities(authorities)
                .build();

        userAuthorityRepository.saveAll(authorities);
        return repository.save(toInsert);
    }

    private List<UserAuthority> getAuthorities(UUID playerId) {
        return List.of(
                new UserAuthority().setRole(Role.ADMIN).setPlayerId(playerId),
                new UserAuthority().setRole(Role.PLAYER).setPlayerId(playerId)
        );
    }

}
