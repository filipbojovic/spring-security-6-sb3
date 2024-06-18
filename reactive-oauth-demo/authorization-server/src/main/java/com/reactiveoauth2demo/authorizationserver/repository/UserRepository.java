package com.reactiveoauth2demo.authorizationserver.repository;

import com.reactiveoauth2demo.authorizationserver.model.Role;
import com.reactiveoauth2demo.authorizationserver.model.User;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface UserRepository extends ReactiveCrudRepository<User, Integer> {

    Mono<User> findByUsername(String username);

    default Mono<User> findByUsername2(String username) {
        var user = new User()
                .setUsername("fika")
                .setPassword("fika")
                .setRole(Role.ADMIN);
        return Mono.just(user);
    }

}
