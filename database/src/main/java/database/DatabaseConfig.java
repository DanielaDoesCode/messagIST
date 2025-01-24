package database;

public class DatabaseConfig {
    final String KEYSTORE_PATH = getEnvOrDefault("KEYSTORE_PATH", "../database-keystore.jks");
    final String TRUSTSTORE_PATH = getEnvOrDefault("TRUSTSTORE_PATH", "../database-truststore.jks");
    final String STORE_PASSWORD = getEnvOrDefault("STORE_PASSWORD", "123456");
    final int DATABASE_PORT = Integer.parseInt(getEnvOrDefault("DATABASE_PORT", "12345"));
    private static String getEnvOrDefault(String key, String defaultValue)
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
}
