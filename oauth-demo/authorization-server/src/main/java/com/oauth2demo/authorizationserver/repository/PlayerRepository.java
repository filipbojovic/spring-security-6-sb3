package com.oauth2demo.authorizationserver.repository;

import com.oauth2demo.authorizationserver.model.Player;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PlayerRepository extends JpaRepository<Player, UUID> {

    Optional<Player> findByEmail(String email);

}
