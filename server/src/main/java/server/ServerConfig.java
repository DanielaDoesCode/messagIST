package server;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class ServerConfig {
    final String KEYSTORE_PATH = getEnvOrDefault("KEYSTORE_PATH", "../server-keystore.jks");
    final String TRUSTSTORE_PATH = getEnvOrDefault("TRUSTSTORE_PATH", "../server-truststore.jks");
    final String STORE_PASSWORD = getEnvOrDefault("STORE_PASSWORD", "123456");
    final int DATABASE_PORT = Integer.parseInt(getEnvOrDefault("DATABASE_PORT", "12345"));
    final String DATABASE_IP = getEnvOrDefault("DATABASE_IP", "192.168.1.1");
    private static final SecretKey JWT_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    private static final String getEnvOrDefault(String key, String defaultValue)
    {
        final String value = System.getenv(key);
        return value != null ? value : defaultValue;
    }

    public String getKEYSTORE_PATH(){
        return this.KEYSTORE_PATH;
    }

    public String getTRUSTSTORE_PATH(){
        return this.TRUSTSTORE_PATH;
    }

    public String getSTORE_PASSWORD(){
        return this.STORE_PASSWORD;
    }

    public SecretKey getJWT_KEY() {return JWT_KEY;}
}
