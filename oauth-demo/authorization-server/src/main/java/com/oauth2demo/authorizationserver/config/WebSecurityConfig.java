package com.oauth2demo.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
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
        return http.formLogin(loginConfigure -> loginConfigure.usernameParameter("fika"))
                .authorizeHttpRequests(authAuthorizer -> authAuthorizer.anyRequest().authenticated())
                .build();
    }

    /**
     * With OAuth2, authorization service manages users and clients. Below are defined users, while clients are
     * defined inside AuthorizationServerConfig
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        var u1 = User.withUsername("fika").password("fika").authorities("read").build();
        var uds = new InMemoryUserDetailsManager();
        uds.createUser(u1);

        return uds;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
