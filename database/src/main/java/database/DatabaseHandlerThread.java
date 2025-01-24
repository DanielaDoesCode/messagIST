package database;

import message.Message;
import message.Opcode;
import com.google.gson.Gson;

import javax.management.RuntimeErrorException;
import javax.net.ssl.SSLSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.List;

public class DatabaseHandlerThread extends Thread {
    private SSLSocket clientSocket;
    private DataInputStream in;
    private DataOutputStream out;
    private KeyStore keyStore;
    private KeyStore trustStore;
    private DatabaseConnector database;
    private Gson gson = new Gson();

    private DatabaseConfig config;

    public DatabaseHandlerThread(SSLSocket accept, KeyStore keyStore, KeyStore trustStore, DatabaseConnector database, DatabaseConfig config) {
        this.clientSocket = accept;
        this.keyStore = keyStore;
        this.trustStore = trustStore;
        this.database = database;
        this.config = config;
    }

    public void run() {
        try {
            System.out.println("[+] DatabaseHandlerThread started and connected to client");
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());

            while (true) {
                String message = in.readUTF();
                option(message);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void option(String message) {
        try {
            switch (Opcode.valueOf(message)) {
                case CHECK_USER:
                    checkUser();
                    break;
                case REGISTER:
                    register();
                    break;
                case CHECK_CREDENTIALS:
                    checkCredentials();
                    break;
                case GET_USERS:
                    getUsers();
                    break;
                case GET_CONTACTS:
                    getContacts();
                    break;
                case UPDATE_CONTACTS:
                    updateContacts();
                    break;
                case GET_MESSAGES_FROM_USER_TO_USER:
                    getMessagesfromUserToUser();
                    break;
                case PUT_MESSAGE:
                    putMessage();
                    break;
                case GET_SALT:
                    getSalt();
                    break;
                case UPDATE_PUBKEY:
                    updatePubKey();
                    break;
                case GET_PUBKEY:
                    getPubKey();
                    break;
                case UPDATE_PRIVKEY:
                    updatePrivKey();
                    break;
                case GET_PRIVKEY:
                    getPrivKey();
                    break;
                default:
                    System.err.printf("Invalid opcode: %s%n", message);
                    break;
            }
        }
        catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
        }
    }

    private void checkUser() {
        try {
            String username = in.readUTF();
            out.writeBoolean(database.checkUser(username));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void register() {
        try {
            String username = in.readUTF();
            String hashedPassword = in.readUTF();
            String salt = in.readUTF();
            database.insertClient(username, hashedPassword, salt, ""); //since it is a new user it wont have contacts
            out.writeUTF(Opcode.REGISTER_SUCCESS.name());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void checkCredentials() {
        try {
            String username = in.readUTF();
            String hashedPassword = in.readUTF();
            out.writeBoolean(database.checkCredentials(username, hashedPassword));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getUsers() {
        // Get all users
        try {
            String[] users = database.getAllClientsUsername();
            StringBuilder sb = new StringBuilder();
            if(users.length != 0){
                for(String user : users){
                    sb.append(user).append("->");
                }
            }
            out.writeUTF(sb.toString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getContacts() {
        try {
            String username = in.readUTF();
            String contacts = database.getContacts(username);
            if (contacts.isEmpty()) {
                out.writeUTF(Opcode.NO_USERS.name());
                return;
            }
            out.writeUTF(contacts);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void updateContacts() {
        try {
            String username = in.readUTF();
            String contactList = in.readUTF();
            database.updateContacts(username, contactList);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getMessagesfromUserToUser() {
        try {
            String sender = in.readUTF();
            String receiver = in.readUTF();
            List<Message> messages = database.getAllMessagesfromUserToUser(sender, receiver);
            out.writeInt(messages.size());
            for (Message message : messages) {
                String messageJson = message.toString();
                out.writeUTF(messageJson);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void putMessage() {
        try {
            String serializedMessage = in.readUTF();
            Message message = new Message(serializedMessage);
            out.writeBoolean(database.insertMessage(message));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getSalt() {
        try {
            String username = in.readUTF();
            String salt = database.getClientSalt(username);
            out.writeUTF(salt);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void updatePubKey() {
        try {
            String username = in.readUTF();
            String pubKey = in.readUTF();
            database.setClientPubKey(username, pubKey);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getPubKey() {
        try {
            String username = in.readUTF();
            out.writeUTF(database.getClientPubKey(username));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void updatePrivKey() {
        try {
            String username = in.readUTF();
            String privKey = in.readUTF();
            database.setClientPrivKey(username, privKey);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void getPrivKey() {
        try {
            String username = in.readUTF();
            out.writeUTF(database.getClientPrivKey(username));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}