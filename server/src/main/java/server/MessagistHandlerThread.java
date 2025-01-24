package server;

import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.*;
import java.security.*;
import java.util.Arrays;
import java.util.logging.Logger;

import java.security.KeyPair;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Base64;
import java.util.*;

import database.DatabaseConnector;
import message.Opcode;

public class MessagistHandlerThread extends Thread {
    private SSLSocket clientSocket;
    private DataInputStream in;
    private DataOutputStream out;
    private DataInputStream dbIn;
    private DataOutputStream dbOut;
    private KeyStore keyStore;
    private KeyStore trustStore;
    private SSLSocket dbSocket;
    private SessionManager sessionManager;

    private ServerConfig config;

    public MessagistHandlerThread(SSLSocket accept, KeyStore keyStore, KeyStore trustStore, SSLSocket dbSocket, ServerConfig config, SessionManager sessionManager) {
        this.clientSocket = accept;
        this.keyStore = keyStore;
        this.trustStore = trustStore;
        this.dbSocket = dbSocket;
        this.config = config;
        this.sessionManager = sessionManager;
    }

    public void run() {
        try {
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            dbIn = new DataInputStream(dbSocket.getInputStream());
            dbOut = new DataOutputStream(dbSocket.getOutputStream());
            String username = ""; // needed to initialize this so the compiler doesn't complain, even though the loop below always runs
            String hashedPassword = "";

            boolean loggedIn = false;
            while (!loggedIn) {
                username = in.readUTF();
                System.out.println("[+] message.Username received: " + username);
                hashedPassword = in.readUTF();
                System.out.println("[+] message.HashedPassword received: " + hashedPassword);
                loggedIn = checkLogin(username, hashedPassword);
            }
            sessionManager.addConnection(username, clientSocket);
            Session session = new Session(username, clientSocket, in, out, dbSocket, sessionManager, config);
            session.interaction();

        } catch (IOException e) {
            System.err.println("[-] Error handling client: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("[-] Error closing client socket: " + e.getMessage());
            }
        }
    }

    public byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public String appendSaltToPassword(String password, byte[] salt) {
        // Convert the salt to a string (Base64 encoding)
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        return saltBase64 + password;
    }

    public boolean checkPassword(String password, String databasePassword, byte[] salt) {
        String clientPassword = appendSaltToPassword(password, salt);
        return databasePassword.equals(clientPassword);
    }

    public boolean checkLogin(String username, String hashedPassword) throws IOException {
        dbOut.writeUTF(Opcode.CHECK_USER.name());
        dbOut.writeUTF(username);
        boolean userExists = dbIn.readBoolean();
        //Checking if user exists in DB
        if (!userExists) {
            //If it does not exist we register it
            if (registerUser(username, hashedPassword)) {
                out.writeUTF(Opcode.REGISTER.name());
                System.out.println("[+] New user was registered");
                dbOut.writeUTF(Opcode.GET_SALT.name());
                dbOut.writeUTF(username);
                out.writeUTF(dbIn.readUTF());
                return true;
                //Error
            } else {
                out.writeUTF(Opcode.ERROR_REGISTERING.name());
                System.err.println("[-] Error registering new user");
                return false;
            }
            //If it exists we check the credentials
        } else {
            dbOut.writeUTF(Opcode.CHECK_CREDENTIALS.name());
            dbOut.writeUTF(username);
            dbOut.writeUTF(hashedPassword);
            boolean credentialsMatch = dbIn.readBoolean();
            if (credentialsMatch) {
                out.writeUTF(Opcode.RETURNING_USER.name());
                System.out.println("[+] Welcome back " + username + "!");
                //getting contacts
                dbOut.writeUTF(Opcode.GET_CONTACTS.name());
                dbOut.writeUTF(username);
                String contacts = dbIn.readUTF();
                if (contacts.equals("NULL")) {
                    out.writeUTF(Opcode.NO_USERS.name());
                } else {
                    out.writeUTF(contacts);
                }
                // send encrypted private key
                dbOut.writeUTF(Opcode.GET_PRIVKEY.name());
                dbOut.writeUTF(username);
                String privKey = dbIn.readUTF();
                out.writeUTF(privKey);
                return true;
            } else {
                out.writeUTF(Opcode.INVALID_CREDENTIALS.name());
                return false;
            }
        }
    }

    public boolean registerUser(String username, String hashedPassword) throws IOException {
        byte[] salt = generateSalt();
        String saltedPassword = appendSaltToPassword(hashedPassword, salt);
        dbOut.writeUTF(Opcode.REGISTER.name());
        dbOut.writeUTF(username);
        dbOut.writeUTF(saltedPassword);
        dbOut.writeUTF(Base64.getEncoder().encodeToString(salt));
        String statusCode = dbIn.readUTF();
        return statusCode.equals(Opcode.REGISTER_SUCCESS.name());
    }

}
