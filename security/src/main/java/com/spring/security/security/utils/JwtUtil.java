package com.spring.security.security.utils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/*merret me krijimin dhe validimin e JWT token-eve për autentikim*/
@Component
public class JwtUtil {

    //🔐 Sekreti 256-bit për HS256
    // përdoret për të nënshkruar JWT token-in.
    private static final String SECRET = "Gm7aZ!qU9vR#T4eLk2YpW@Ns3HxCzM8D";
    //vetëm serveri yt e di këtë vlerë dhe e përdor për
    // të nënshkruar dhe kontrolluar nëse një JWT është i saktë
    private SecretKey key;

    private static final long EXPIRATION_TIME = 86400000; // 1 ditë në ms

    @PostConstruct
    public void initKey() {
        // inicializo çelësin një herë
        this.key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    // gjeneruar një JWT token për një përdorues të dhënë
    //jwt përdoret për autentikim, për të vërtetuar që
    // përdoruesi është loguar dhe ka të drejtë për të përdorur API-të
    public String generateToken(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    // Të lexojë dhe verifikojë JWT token-in që merr si argument,
    // dhe të nxjerrë prej tij emrin e përdoruesit që është ruajtur
    // në momentin e gjenerimit të token-it
    public String extractUsername(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            System.out.println("⚠️ Token ka skaduar: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.out.println("❌ Token i pavlefshëm: " + e.getMessage());
            throw e;
        }
    }

    // ✅ Kontrollon nëse token-i është valid për këtë përdorues
    public boolean isTokenValid(String token, String username) {
        try {
            String extracted = extractUsername(token);
            return extracted.equals(username);
        } catch (Exception e) {
            return false;
        }
    }
}
