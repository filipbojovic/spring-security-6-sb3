package com.workshop.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "2253456cf57230aabc5c1651a7c1662da1afd139c0a9305cb840db181b84f2db";

    public String extractUsername(String token) {
        // the subject is username of user
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);

        return claimsResolver.apply(claims);
    }

    /**
     * It is used when creation of a token without claims is required
     *
     * @param userDetails
     * @return
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * SignWith property is important -> here it is specified which key to use to encode/decode the jwt
     *
     * @param extraClaims Contains the claims we want to add
     * @param userDetails
     * @return
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(
                        System.currentTimeMillis())) // when this claim was created, and it will be used to calculate the expiration date or to check if the token is still valid or not
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // valid for 24h + 1000ms
                .signWith(getSignInKey(),
                        SignatureAlgorithm.HS256) // specify the SignIn key that will be used to decode and also to decode the token later
                .compact(); // it will generate and return the token
    }

    /**
     * Firstly check whether the username from userDetails is the same as the username from the token.
     * Secondly check whether the token has expired by extracting the Expiration claim from it.
     *
     * @param token
     * @param userDetails
     * @return
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * By using the SignIn key, it will extract all the claims from the token.
     *
     * @param token
     * @return
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // to generate/decode the token we need to use a signing key (~50min)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }

}
