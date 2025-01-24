package client;

import message.Message;
import message.Opcode;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import messagistSecureDoc.SecureDocument;

public class MessagistClient {
    private static List<String> contacts = new ArrayList<>();
    private static int contactsNum = 0;
    private static PasswordDerivationService service;

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static void main(String[] args) {
        ClientLocalStorage localStorage = null;
        String username = null;
        try {
            System.setProperty("https.protocols", "TLSv1.2");
            ClientConfig config = new ClientConfig();
            localStorage = new ClientLocalStorage();

            // Load keystore and truststore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreStream = new FileInputStream(config.KEYSTORE_PATH)) {
                keyStore.load(keyStoreStream, config.STORE_PASSWORD.toCharArray());
            }

            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (FileInputStream trustStoreStream = new FileInputStream(config.TRUSTSTORE_PATH)) {
                trustStore.load(trustStoreStream, config.STORE_PASSWORD.toCharArray());
            }

            // Initialize KeyManager and TrustManager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, config.STORE_PASSWORD.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Create SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            // Create secure socket
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(config.SERVER_IP, 9999);
            socket.startHandshake();

            System.out.println("[+] Connected to the server");

            try (DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                 DataInputStream in = new DataInputStream(socket.getInputStream());
                 BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

                //E2E Thread
                Thread e2eCommunicationThread = new Thread(new E2EConnectionListener(localStorage, out, in));
                e2eCommunicationThread.start();

                boolean loggedIn = false;
                while (!loggedIn) {
                    username = login(reader, out, in);
                    loggedIn = (username.equals("")) ? false : true;
                }


                interaction(reader, out, in, keyManagerFactory, trustManagerFactory, localStorage, username);
            }
        } catch (Exception e) {
            System.err.println("[-] Client error: " + e.getMessage());
            e.printStackTrace();
        }

    }

    public static String login(BufferedReader reader, DataOutputStream out, DataInputStream in) throws Exception {
        String username;
        String password;

        while (true) {
            System.out.print("Enter username: ");
            username = reader.readLine();

            if (!isValidUsername(username)) {
                continue;
            }
            System.out.print("Enter password: ");
            password = reader.readLine();
            if (!isPasswordValid(password)) {
                continue;
            }
            break;
        }

        // Hash the password
        String hashedPassword = hashPassword(password);

        // Send login credentials
        out.writeUTF(username);
        out.writeUTF(hashedPassword);

        // Read server response
        String response = in.readUTF();
        if (response.equals(Opcode.REGISTER.name())) {
            System.out.println("[+] New user was registered");

            String salt = in.readUTF();
            String masterPassword;
            while (true) {
                System.out.println("Enter the password to recover your authenticator: ");
                masterPassword = reader.readLine();
                if (isPasswordValid((masterPassword))) {
                    break;
                }
            }

            service = new PasswordDerivationService(masterPassword, salt);
            SecretKey recoveryKey = service.deriveSecretKey();
            KeyPair clientKeyPair = service.generateKeyPair();
            String privateKey = service.encryptPrivateKey(clientKeyPair.getPrivate(), recoveryKey);
            service.setKeyPair(clientKeyPair);
            
            sendPubKeyToServer(out);
            sendPrivKeyToServer(out, privateKey);
            return username;
        } else if (response.equals(Opcode.RETURNING_USER.name())) {
            System.err.println("[+] Welcome back " + username + "!");
            String contacts = in.readUTF();
            if (contacts.equals(Opcode.NO_USERS.name())) {
                System.out.println("No contacts found of user: " + username);
            } else {
                extractContacts(contacts);
            }
            recoverAuthenticator(reader, out, in, username);
            return username;
        } else if (response.equals(Opcode.INVALID_CREDENTIALS.name())) {
            System.err.println("[-] Invalid credentials");
            return "";
        } else {
            System.err.println("[-] Error logging in: " + response);
            return "";
        }
    }

    public static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("[-] Error hashing password: " + e.getMessage(), e);
        }
    }

    public static void interaction(BufferedReader reader, DataOutputStream out, DataInputStream in, KeyManagerFactory keyManagerFactory, TrustManagerFactory trustManagerFactory, ClientLocalStorage localStorage, String username) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, KeyManagementException {
        art();
        while (true) {
            System.out.println("-> add contact: type 'a'.");
            System.out.println("-> send message: type 's'.");
            System.out.println("-> send end-to-end message: type 'e'.");
            System.out.println("-> quit: type 'q'.");
            System.out.println("-> help: type 'h'.");
            System.out.println("-------------------------");
            System.out.println("My Contacts: ");
            printContacts();
            System.out.println("-------------------------");
            System.out.print("Enter an option: ");
            String message = reader.readLine();

            option(message, in, out, reader, keyManagerFactory, trustManagerFactory, localStorage, username);
        }
    }

    public static void option(String message, DataInputStream in, DataOutputStream out, BufferedReader reader, KeyManagerFactory keyManagerFactory, TrustManagerFactory trustManagerFactory, ClientLocalStorage localStorage, String username) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, KeyManagementException {
        switch (message) {
            case "a":
                addContact(in, out, reader);
                break;
            case "s":
                sendMessage(in, out, reader);
                break;
            case "e":
                sendE2EMessage(in, out, reader, localStorage, username);
                break;
            case "q":
                quit();
                break;
            case "h":
                help();
                break;
            default:
                System.err.println("[-] Invalid option");
                System.err.println("[-] Type 'h' for help");
        }
    }

    public static void addContact(DataInputStream in, DataOutputStream out, BufferedReader reader) throws IOException {
        out.writeUTF(Opcode.GET_POSSIBLE_CONTACTS.name());
        String[] possible_contacts = in.readUTF().split("->");
        System.out.println("Available contacts:");
        for (int i = 0; i < possible_contacts.length; i++) {
            System.out.println(i + "->" + possible_contacts[i]);
        }
        System.out.println("Enter the number of the contact you want to add:");
        int contact;
        try {
            contact = Integer.parseInt(reader.readLine());
        } catch (NumberFormatException e) {
            System.err.println("[-] Invalid contact number");
            return;
        }
        if (contact >= possible_contacts.length || contact < 0) {
            System.err.println("[-] Invalid contact number");
            return;
        } else if (contacts.contains(possible_contacts[contact])) {
            System.err.println("[-] Contact already added");
            return;
        }
        out.writeUTF(Opcode.ADD_CONTACT.name());
        out.writeUTF(possible_contacts[contact]);

        String response = in.readUTF();
        if (response.equals(Opcode.OK.name())) {
            contacts.add(possible_contacts[contact]);
            System.out.println("[+] Contact added successfully");
        } else {
            System.out.println("Fail, please try again :(");
        }
    }

    public static void sendMessage(DataInputStream in, DataOutputStream out, BufferedReader reader) throws IOException, ClassNotFoundException {
        System.out.println("List of contacts:");
        printContacts();
        System.out.println("Enter the number of the contact you want to send a message to:");
        int contact = Integer.parseInt(reader.readLine());

        printChat(in, out, contacts.get(contact)); // Show messages with this contact

        System.out.println("Enter the message you want to send:");
        String content = reader.readLine();

        Message message = new Message(content, contacts.get(contact));
        SecureDocument secureMessage = new SecureDocument(message.toString());

        out.writeUTF(Opcode.GET_PUBKEY.name());
        out.writeUTF(contacts.get(contact));
        String encodedRecipientKey = in.readUTF();
        PublicKey recipientKey;
        try {
            recipientKey = readPublicKey(Base64.getDecoder().decode(encodedRecipientKey));
        } catch (Exception e) {
            System.err.println("Failed to decode recipient public key: " + e.getMessage());
            return;
        }
        try {
            secureMessage.protect(recipientKey, service.getKeyPair().getPrivate(), service.getKeyPair().getPublic());
        } catch (Exception e) {
            System.err.println("Failed to protect message: " + e.getMessage());
            return;
        }

        message = new Message(secureMessage.getMessage());
        out.writeUTF(Opcode.SEND_MESSAGE.name());
        out.writeUTF(message.toString());

        String response = in.readUTF();
        if (response.equals("NO-OK")) {
            System.out.println("Fail, please try again :(");
        }

    }

    private static PublicKey readPublicKey(byte[] pubEncoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
    }

    public static void sendE2EMessage(DataInputStream in, DataOutputStream out, BufferedReader reader, ClientLocalStorage localStorage, String username) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, KeyManagementException {
        System.out.println("List of contacts:");
        printContacts();
        System.out.println("Enter the number of the contact you want to send a message to:");
        int contact = Integer.parseInt(reader.readLine());

        //The difference between the e2e chat is that it goes into the local storage to get what it needs
        printLocalE2EChat(in, out, contacts.get(contact), localStorage, username);

        System.out.println("Enter the message you want to send:");
        String content = reader.readLine();

        Message message = new Message(content, contacts.get(contact));
        message.setSender(username);
        SecureDocument secureMessage = new SecureDocument(message.toString());

        out.writeUTF(Opcode.GET_PUBKEY.name());
        out.writeUTF(contacts.get(contact));
        String encodedRecipientKey = in.readUTF();
        PublicKey recipientKey;
        try {
            recipientKey = readPublicKey(Base64.getDecoder().decode(encodedRecipientKey));
        } catch (Exception e) {
            System.err.println("Failed to decode recipient public key: " + e.getMessage());
            return;
        }
        try {
            secureMessage.protect(recipientKey, service.getKeyPair().getPrivate(), service.getKeyPair().getPublic());
        } catch (Exception e) {
            System.err.println("Failed to protect message: " + e.getMessage());
            return;
        }

        message = new Message(secureMessage.getMessage());

        //Get the address of the receiver

        out.writeUTF(Opcode.SEND_E2E_MESSAGE.name());
        out.writeUTF(contacts.get(contact));

        String receiver_address = in.readUTF();
        System.out.println("Receiver address: " + receiver_address);

        out.writeUTF(Opcode.OK.name());

        //We need to receive a token from the server to authenticate ourselves
        String token = in.readUTF();
        System.out.println("Token: " + token);

        // Create socket - 7777 is the PORT that clients are expected to receive E2E connections in
        Socket socket = new Socket(receiver_address, 7777);

        //Send the token and message to the receiver
        DataOutputStream out2 = new DataOutputStream(socket.getOutputStream());
        out2.writeUTF(token);
        out2.writeUTF(message.toString());

        DataInputStream in2 = new DataInputStream(socket.getInputStream());
        String response = in2.readUTF();
        if (response.equals("NO-OK")) {
            System.out.println("Fail, please try again :(");
        }
        else {
            localStorage.insertMessages(message);
        }
    }

    private static void printLocalE2EChat(DataInputStream in, DataOutputStream out, String contact, ClientLocalStorage localStorage, String username) throws IOException {
        List<Message> messages = localStorage.getAllMessagesfromUserToUser(username, contact);
        List<Message> receivedMessages = localStorage.getAllMessagesfromUserToUser(contact, username);
        for (Message message : receivedMessages) {
            messages.add(message);
        }

        messages.sort(new Comparator<Message>() {
            public int compare(Message m1, Message m2) {
                return m1.getTimestamp().isBefore(m2.getTimestamp()) ? -1 : 1;
            }
        });

        for (Message message : messages) {
            if (message.isEncrypted()) {
                SecureDocument secureMessage = new SecureDocument(message.toString());
                out.writeUTF(Opcode.GET_PUBKEY.name());
                out.writeUTF(message.getSender());
                String encodedSenderKey = in.readUTF();
                PublicKey senderKey;
                try {
                    senderKey = readPublicKey(Base64.getDecoder().decode(encodedSenderKey));
                } catch (Exception e) {
                    System.err.println("Failed to decode sender public key: " + e.getMessage());
                    continue;
                }
                try {
                    boolean useSenderKey = message.getReceiver().equals(contact);
                    secureMessage.unprotect(service.getKeyPair().getPrivate(), senderKey, useSenderKey);
                } catch (Exception e) {
                    System.err.println("Failed to unprotect message: " + e.getMessage());
                    continue;
                }
                message = new Message(secureMessage.getMessage());
                System.out.printf("%s [*]: %s%n", message.getSender(), message.getContent());
            } else {
                System.out.printf("%s: %s%n", message.getSender(), message.getContent());
            }
        }
    }

    public static void quit() {
        System.out.println("[+] Quitting...");
        System.exit(0);
    }

    public static void help() {
        art();
        System.out.println("-> add contact: type 'a'.");
        System.out.println("-> send message: type 's'.");
        System.out.println("-> send end-to-end message: type 'e'.");
        System.out.println("-> quit: type 'q'.");
        System.out.println("-> help: type 'h'.");
    }

    private static void printChat(DataInputStream in, DataOutputStream out, String contactName) throws IOException, ClassNotFoundException {
        List<Message> messages = new ArrayList<>();

        out.writeUTF(Opcode.GET_MESSAGES.name());
        out.writeUTF(contactName);
        int messageCount = in.readInt();
        for (int i = 0; i < messageCount; i++) {
            String serializedMessage = in.readUTF();
            Message message = new Message(serializedMessage);
            messages.add(message);
        }

        messages.sort(new Comparator<Message>() {
            public int compare(Message m1, Message m2) {
                return m1.getTimestamp().isBefore(m2.getTimestamp()) ? -1 : 1;
            }
        });

        for (Message message : messages) {
            if (message.isEncrypted()) {
                SecureDocument secureMessage = new SecureDocument(message.toString());
                out.writeUTF(Opcode.GET_PUBKEY.name());
                out.writeUTF(message.getSender());
                String encodedSenderKey = in.readUTF();
                PublicKey senderKey;
                try {
                    senderKey = readPublicKey(Base64.getDecoder().decode(encodedSenderKey));
                } catch (Exception e) {
                    System.err.println("Failed to decode sender public key: " + e.getMessage());
                    continue;
                }
                try {
                    boolean useSenderKey = message.getReceiver().equals(contactName);
                    secureMessage.unprotect(service.getKeyPair().getPrivate(), senderKey, useSenderKey);
                } catch (Exception e) {
                    System.err.println("Failed to unprotect message: " + e.getMessage());
                    continue;
                }
                message = new Message(secureMessage.getMessage());
                System.out.printf("%s [*]: %s%n", message.getSender(), message.getContent());
            } else {
                System.out.printf("%s: %s%n", message.getSender(), message.getContent());
            }
        }
    }

    public static void printContacts() {
        int i = 0;
        if (!contacts.isEmpty()) {
            for (String contacts : contacts) {
                System.out.println(i + "->" + contacts);
                i++;
            }
        }
    }

    public static void extractContacts(String contactString) {
        String[] contactsArray = contactString.split("->");
        for (String contact : contactsArray) {
            contacts.add(contact);
        }
    }
    private static void recoverAuthenticator(BufferedReader reader, DataOutputStream out, DataInputStream in, String username) throws Exception {
        try {
            String receivedPrivateKey = in.readUTF();
            
            System.out.println("Enter the password to recover your authenticator:");
            String masterPassword = reader.readLine();
            out.writeUTF(Opcode.GET_SALT.name());
            String salt = in.readUTF();

            service = new PasswordDerivationService(masterPassword, salt);
            SecretKey recoveryKey = service.deriveSecretKey();
            PrivateKey privateKey = service.decryptPrivateKey(receivedPrivateKey, recoveryKey);

            out.writeUTF(Opcode.GET_PUBKEY.name());
            out.writeUTF(username);
            String encodedPublicKey = in.readUTF();
            PublicKey publicKey = readPublicKey(Base64.getDecoder().decode(encodedPublicKey));

            service.setKeyPair(new KeyPair(publicKey, privateKey));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendPubKeyToServer(DataOutputStream out) throws IOException {
        out.writeUTF(Opcode.UPDATE_PUBKEY.name());
        out.writeUTF(Base64.getEncoder().encodeToString(service.getKeyPair().getPublic().getEncoded()));
    }

    private static void sendPrivKeyToServer(DataOutputStream out, String privateKey) throws IOException {
        out.writeUTF(Opcode.UPDATE_PRIVKEY.name());
        out.writeUTF(privateKey);
    }

    public static boolean isValidUsername(String username) {
        Pattern pattern = Pattern.compile("^ist\\d+", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(username);
        boolean matchFound = matcher.find();
        if (matchFound) {
            System.out.println("Valid IST ID");
        } else {
            System.err.println("Invalid IST ID. The username must start with 'ist' followed by numbers only.");
        }
        return matchFound;
    }

    public static boolean isPasswordValid(String password) {
        if (password.length() < 12) {
            System.out.println("Password must be at least 12 characters long.");
            return false;
        }

        // Flags for complexity requirements
        boolean hasUpperCase = false;
        boolean hasLowerCase = false;
        boolean hasDigit = false;
        boolean hasSpecialChar = false;

        // Special characters set
        String specialCharacters = "!@#$%^&*()-_+=<>?/{}[]~`|\\,.;:\"'";

        for (char ch : password.toCharArray()) {
            if (Character.isUpperCase(ch)) {
                hasUpperCase = true;
            } else if (Character.isLowerCase(ch)) {
                hasLowerCase = true;
            } else if (Character.isDigit(ch)) {
                hasDigit = true;
            } else if (specialCharacters.contains(String.valueOf(ch))) {
                hasSpecialChar = true;
            }
            if (hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar) {
                break;
            }
        }

        if (!hasUpperCase) {
            System.out.println("Password must contain at least one uppercase letter.");
        }
        if (!hasLowerCase) {
            System.out.println("Password must contain at least one lowercase letter.");
        }
        if (!hasDigit) {
            System.out.println("Password must contain at least one number.");
        }
        if (!hasSpecialChar) {
            System.out.println("Password must contain at least one special character.");
        }

        return hasUpperCase && hasLowerCase && hasDigit && hasSpecialChar;
    }

    public static void art(){
        System.out.println("\n" +
                "\n" +
                "  __  __                           _____  _____ _______ \n" +
                " |  \\/  |                         |_   _|/ ____|__   __|\n" +
                " | \\  / | ___  ___ ___  __ _  __ _  | | | (___    | |   \n" +
                " | |\\/| |/ _ \\/ __/ __|/ _` |/ _` | | |  \\___ \\   | |   \n" +
                " | |  | |  __/\\__ \\__ \\ (_| | (_| |_| |_ ____) |  | |   \n" +
                " |_|  |_|\\___||___/___/\\__,_|\\__, |_____|_____/   |_|   \n" +
                "                              __/ |                     \n" +
                "                             |___/                      \n" +
                "\n");
    }
}
