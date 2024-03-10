package com.oauth2demo.authorizationserver.repository;

import com.oauth2demo.authorizationserver.model.UserAuthority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserAuthorityRepository extends JpaRepository<UserAuthority, UUID> {
}
