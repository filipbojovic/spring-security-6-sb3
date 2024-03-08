package com.oauth2demo.authorizationserver.service;

import com.oauth2demo.authorizationserver.repository.PlayerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * With OAuth2, authorization service manages users and clients. Below are defined users, while clients are
 * defined inside AuthorizationServerConfig
 */
@Service
@RequiredArgsConstructor
public class AbstractUserDetailsService implements UserDetailsService {

    private final PlayerRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User hasn't been found."));
    }

}
