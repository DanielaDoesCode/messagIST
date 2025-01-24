package database;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class DatabaseServer {
    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException {
        System.setProperty("https.protocols", "TLSv1.2");
        SSLServerSocket socket = null;
        final DatabaseConnector database = new DatabaseConnector();
        final DatabaseConfig config = new DatabaseConfig();

        //Loading Stores
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream inputStream1 = new FileInputStream(config.KEYSTORE_PATH);
        keystore.load(inputStream1, config.STORE_PASSWORD.toCharArray());

        KeyStore truststore = KeyStore.getInstance("JKS");
        FileInputStream inputStream2 = new FileInputStream(config.TRUSTSTORE_PATH);
        truststore.load(inputStream2, config.STORE_PASSWORD.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, config.STORE_PASSWORD.toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(truststore);

        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        // Initial delay = 0 days, interval = 14 days
        scheduler.scheduleAtFixedRate(() -> {
            System.out.println("Running scheduled database backup...");
            database.backupDatabase("./backup");
        }, 0, 14, TimeUnit.DAYS);
        System.out.println("Backup scheduler started. Backups will occur every 14 days.");

        try{
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            SSLServerSocketFactory sslServerSocketFactory = context.getServerSocketFactory();
            socket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(config.DATABASE_PORT);

            System.out.println("[+] DatabaseServer started at port " + config.DATABASE_PORT + "...waiting for connection");
            while (true) {
                SSLSocket clientSocket = (SSLSocket) socket.accept();
                new DatabaseHandlerThread(clientSocket, keystore, truststore, database, config).start();
            }
        } catch (KeyManagementException | NoSuchAlgorithmException | IOException e) {
            System.err.println("[-] Error starting DatabaseServer: " + e.getMessage());
        }
    }
}
