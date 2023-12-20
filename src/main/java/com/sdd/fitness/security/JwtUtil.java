package com.sdd.fitness.security;

import com.sdd.fitness.constant.Message;
import com.sdd.fitness.exception.ResponseStatusException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${com.sdd.fitness.jwt.issuer}")
    private String issuer;

    @Value("${com.sdd.fitness.jwt.auth-expirate}")
    private Integer authTokenExpired;

    @Value("${com.sdd.fitness.jwt.validation-expirate}")
    private Integer validationTokenExpired;

    private final KeyPair key;

    public JwtUtil(@Qualifier("key") KeyPair key) {
        this.key = key;
    }

    public String getTokenFromBearer(String bearer) throws ResponseStatusException {
        String[] bearerParse = bearer.split(" ");

        if (bearerParse.length != 2) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.JWT_TOKEN_INVALID);
        }

        if (!bearerParse[0].equals("Bearer")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, Message.JWT_TOKEN_INVALID);
        }

        return bearerParse[1];
    }

    public String getBearerFromHeader(HttpServletRequest request) throws ResponseStatusException {
        String authorizationHeaderBearer = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeaderBearer == null) {
            return null;
        }

        return getTokenFromBearer(authorizationHeaderBearer);
    }

    public boolean validateToken(String token) throws ExpiredJwtException {
        try {
            Jwts.parser()
                    .verifyWith(key.getPublic())
                    .build()
                    .parse(token);

            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public String getEmailFromBearer(String bearer) throws MalformedJwtException {
        String token = getTokenFromBearer(bearer);

        return getEmailFromToken(token);
    }

    public String getEmailFromToken(String token) {
        Claims parsedJwt = Jwts.parser()
                .verifyWith(key.getPublic())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return parsedJwt.getSubject();
    }

    public String generateTokenAuth(String email) {
        return generateToken(email, authTokenExpired);
    }

    public String generateTokenValidationOrTokenReset(String email) {
        return generateToken(email, validationTokenExpired);
    }

    private String generateToken(String email, int expiredMils) {
        expiredMils = expiredMils * 60 * 1000;
        Date currentDate = new Date();
        Date expDate = new Date(currentDate.getTime() + expiredMils);

        return Jwts.builder()
                .subject(email)
                .issuer(issuer)
                .issuedAt(currentDate)
                .expiration(expDate)
                .signWith(key.getPrivate())
                .compact();
    }
}
