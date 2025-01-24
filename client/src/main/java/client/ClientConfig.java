package client;

public class ClientConfig {
    final String KEYSTORE_PATH = getEnvOrDefault("KEYSTORE_PATH", "../client-keystore.jks");
    final String TRUSTSTORE_PATH = getEnvOrDefault("TRUSTSTORE_PATH", "../client-truststore.jks");
    final String STORE_PASSWORD = getEnvOrDefault("STORE_PASSWORD", "123456");
    final int E2E_PORT = 7777;
    final String SERVER_IP = getEnvOrDefault("SERVER_IP", "192.168.0.10");

    private static final String getEnvOrDefault(String key, String defaultValue)
    {
        final String value = System.getenv(key);
        return value != null ? value : defaultValue;
    }

}
