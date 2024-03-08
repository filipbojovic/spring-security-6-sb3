package com.oauth2demo.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    /**
     * Before the WebSecurityConfig would have extended WebSecurityConfigurerAdapterClass which is deprecated, and
     * definition of SecurityFilterChain bean is the new approach
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        return http.formLogin(loginConfigure -> loginConfigure.usernameParameter("fika"))
        return http.authorizeHttpRequests(authAuthorizer -> authAuthorizer.anyRequest().permitAll()).build();
//        return http.authorizeHttpRequests(authAuthorizer -> authAuthorizer
//                        .requestMatchers("/api/v1/player/**").permitAll()
//                        .anyRequest().authenticated())
//                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
