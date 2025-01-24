package server;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class TokenService {
    private ServerConfig config;
    public TokenService(ServerConfig config) {
        this.config = config;
    }

    public String generateToken(String sender, String receiver){
        return Jwts.builder()
                .setSubject("E2E-connection")
                .claim("sender", sender)
                .claim("receiver", receiver)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000)) // 1 min expiry
                .signWith(config.getJWT_KEY())
                .compact();
    }

    public boolean validateToken(String token){
        try {
            Jwts.parserBuilder()
                    .setSigningKey(config.getJWT_KEY())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            // whichever exception is thrown, the token is not valid
            // it may be due to it being expired or not signed with the correct key
            return false;
        }
    }
}
