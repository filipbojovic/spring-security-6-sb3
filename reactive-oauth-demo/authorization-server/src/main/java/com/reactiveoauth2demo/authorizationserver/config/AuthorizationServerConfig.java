package com.reactiveoauth2demo.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.List;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    public ReactiveClientRegistrationRepository clientRegistrations() {
        return new InMemoryReactiveClientRegistrationRepository(List.of(
                // Define your client registration here
                ClientRegistration.withRegistrationId("your-client")
                        .clientId("your-client-id")
                        .clientSecret("your-client-secret")
                        .scope("openid", "profile")
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                        .authorizationUri("https://your-issuer-uri/oauth/authorize")
                        .tokenUri("https://your-issuer-uri/oauth/token")
                        .userInfoUri("https://your-issuer-uri/userinfo")
                        .jwkSetUri("https://your-issuer-uri/.well-known/jwks.json")
                        .issuerUri("https://your-issuer-uri")
                        .build()
        ));
    }

}
