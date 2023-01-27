package com.security.springsecurity6.config;

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

    private static final String SECRET_KEY = "46294A404E635266556A586E3272357538782F4125442A472D4B615064536756";

    public String extractUsername(String token){
        return extreactClaim(token, Claims::getSubject);
    }

    /**
     *
     * @param token
     * @param claimsResolver
     * @return um Claim "corpo" jwt
     * @param <T>
     */
    public <T> T extreactClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     *
     * @param userDetails
     * @return token gerado sem Claims, apenas com o userDetails
     */
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     *
     * @param extraClaims
     * @param userDetails
     * @return token gerado, que ira expirar em 24hrs
     */
    public String generateToken(Map<String, Object> extraClaims,
                                UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    /**
     *
     * @param token
     * @param userDetails
     * @return valida se o token pertence ao usuario correto
     */
    public boolean isTokenValid(String token, UserDetails userDetails){
       final String username = extractUsername(token);
       return (username.equals(userDetails.getUsername())) && !isTokenExperied(token);
    }

    /**
     *
     * @param token
     * @return se o token do usuario esta expirado
     */
    private boolean isTokenExperied(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     *
     * @param token
     * @return Data de expiracao do token
     */
    private Date extractExpiration(String token) {
        return extreactClaim(token, Claims::getExpiration);
    }

    /**
     *
     * @param token
     * @return todos os Cliams "corpo" do jwt
     */
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
