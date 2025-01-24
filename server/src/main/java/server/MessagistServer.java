package server;

import javax.net.ssl.*;
import java.security.*;
import java.io.*;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.GeneralSecurityException;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import database.DatabaseConnector;


public class MessagistServer {

    public static void main(String[] args) throws UnrecoverableKeyException, CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        System.setProperty("https.protocols", "TLSv1.2");
        //final DatabaseConnector database = new DatabaseConnector();
        final SessionManager sessionManager = new SessionManager();
        SSLServerSocket socket = null;
        ServerConfig config = new ServerConfig();

        //Loading Stores
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream inputStream1 = new FileInputStream(config.KEYSTORE_PATH);
        keyStore.load(inputStream1, config.STORE_PASSWORD.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        FileInputStream inputStream2 = new FileInputStream(config.TRUSTSTORE_PATH);
        trustStore.load(inputStream2, config.STORE_PASSWORD.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, config.STORE_PASSWORD.toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        //Starting Server
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(9999);

            // Connect to DatabaseServer
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket dbSocket = (SSLSocket) factory.createSocket(config.DATABASE_IP, config.DATABASE_PORT);
            System.out.println("[+] Connected to DatabaseServer at port 12345");

            System.out.println("[+] Server started at port 9999...waiting for connection");
            while (true) {
                new MessagistHandlerThread((SSLSocket) serverSocket.accept(), keyStore, trustStore, dbSocket, config, sessionManager).start();
            }
        } catch (Exception e) {
            System.err.println("[-] Error starting server: " + e.getMessage());
            System.exit(-1);
        }
    }
}