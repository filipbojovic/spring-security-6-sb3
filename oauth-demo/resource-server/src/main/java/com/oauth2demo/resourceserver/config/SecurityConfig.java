package com.oauth2demo.resourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    /**
     * Here is is configured that it uses jwt tokens and we set where to find public key by using jwkSetUri?
     *
     * @param http
     * @return
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.oauth2ResourceServer(
                        oauthConfigurer -> oauthConfigurer
                                .jwt(jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:8080/oauth2/jwks"))
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .build();
    }
}
