package com.oauth2demo.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.oauth2demo.authorizationserver.config.keys.JwksKeys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class OAuth2Configuration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) //
    public SecurityFilterChain oAuth2SecurityFilterChain(HttpSecurity http) throws Exception {
        // pre-configuration approach which configures everything we need to have configured
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));

        return http.formLogin(conf -> conf.usernameParameter("fika"))
                .build();
    }

    /**
     * Very similar to UserDetailsService, but instead of managing users here, clients are defined because each
     * client has to be known to the authorization server, otherwise a client won't be able to use the authorization
     * server.
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        var rc = RegisteredClient
                .withId(UUID.randomUUID().toString()) // is just the identifier of a record in the authorization server, not the actual client id
                .clientId("client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:3000/authorized") // when authorization endpoint has been called and user has been authorized successfully, the authorization server will redirect back to FE url
                .scope(OidcScopes.OPENID) // use set of rules defined by the OPENID protocol? It is possible to specify ours, e.g. "ADMIN"
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
//                        .accessTokenTimeToLive(Duration.ofHours(10))
                        .refreshTokenTimeToLive(Duration.ofHours(10))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(rc);
    }

    /**
     * This was ProviderSettings before it was deprecated. It is used to override endpoints:
     * Some of the defaults are:
     * .authorizationEndpoint("/oauth2/authorize")
     * .tokenEndpoint("/oauth2/token")
     * .jwkSetEndpoint("/oauth2/jwks")
     * }
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings
                .builder()
                .issuer("http://localhost:8080")
                .build();
    }

    /**
     * Authorization server uses private/public key pair. The private key is used by the authorization server to
     * sign the tokens, while the public one is used by a resource server to decode them. For that JWKSource bean
     * must be defined.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = JwksKeys.generateRSAKey();
        JWKSet set = new JWKSet(rsaKey);
        return (selector, securityContext) -> selector.select(set);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

}
