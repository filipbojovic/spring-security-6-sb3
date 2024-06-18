package com.reactiveoauth2demo.authorizationserver.config;

import com.reactiveoauth2demo.authorizationserver.model.User;
import com.reactiveoauth2demo.authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class WebSecurityConfiguration {

    private final UserRepository userRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();
    }

//    @Bean
//    public ReactiveUserDetailsService userDetailsService() {
//        return username -> userRepository.findByUsername2(username)
//                .map(obj -> UserDetails.class.cast(obj))
//                .switchIfEmpty(Mono.defer(() -> Mono.error(new UsernameNotFoundException("User not found"))));
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    protected ReactiveAuthenticationManager reactiveAuthenticationManager(PasswordEncoder passwordEncoder) {

        return authentication -> userRepository.findByUsername2(authentication.getPrincipal().toString())
                .switchIfEmpty(Mono.error(() -> new UsernameNotFoundException("User not found")))
                .flatMap(user -> callMethod(passwordEncoder, authentication, user));
    }

    private Mono<UsernamePasswordAuthenticationToken> callMethod(
            PasswordEncoder passwordEncoder, Authentication authentication, User user) {
        final String username = authentication.getPrincipal().toString();
        final CharSequence rawPassword = authentication.getCredentials().toString();

        if (passwordEncoder.matches(rawPassword, user.getPassword())) {

            log.info("User has been authenticated {}", username);
            return Mono.just(new UsernamePasswordAuthenticationToken(
                    username, user.getPassword(), user.getAuthorities()));
        }

        log.error("Wrong credentials!");
        //This constructor can be safely used by any code that wishes to create a UsernamePasswordAuthenticationToken, as the isAuthenticated() will return false.
        var token = new UsernamePasswordAuthenticationToken(username, authentication.getCredentials());
        return Mono.just(token);
//        return Mono.error(() -> new UsernameNotFoundException("User not found"));
    }

//    @Bean
//    public ReactiveAuthenticationManager reactiveAuthenticationManager(AuthenticationConfiguration config) {
//        return config.
//    }

//    @Bean
//    public WebClient webClient(ReactiveClientRegistrationRepository clientRegistrations,
//            ServerOAuth2AuthorizedClientRepository authorizedClients) {
//        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
//                new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrations, authorizedClients);
//        return WebClient.builder()
//                .filter(oauth2)
//                .build();
//    }
//
//    @Bean
//    public ReactiveClientRegistrationRepository clientRegistrations() {
//        return new InMemoryReactiveClientRegistrationRepository(List.of(
//                // Define your client registration here
//                ClientRegistration.withRegistrationId("your-client")
//                        .clientId("your-client-id")
//                        .clientSecret("your-client-secret")
//                        .scope("openid", "profile")
//                        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
//                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
//                        .authorizationUri("https://your-issuer-uri/oauth/authorize")
//                        .tokenUri("https://your-issuer-uri/oauth/token")
//                        .userInfoUri("https://your-issuer-uri/userinfo")
//                        .jwkSetUri("https://your-issuer-uri/.well-known/jwks.json")
//                        .issuerUri("https://your-issuer-uri")
//                        .build()
//        ));
//    }

}