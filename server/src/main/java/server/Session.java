package server;

import com.google.gson.Gson;
import message.Message;
import message.Opcode;

import javax.net.ssl.SSLSocket;
import java.io.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Session {
    private String username;
    private SSLSocket clientSocket;
    private DataInputStream in;
    private DataOutputStream out;
    private DataInputStream dbIn;
    private DataOutputStream dbOut;
    private SSLSocket dbSocket;
    private SessionManager sessionManager;
    private Gson gson;
    private TokenService tokenService;

    public Session(String username, SSLSocket clientSocket, DataInputStream in, DataOutputStream out, SSLSocket dbSocket, SessionManager sessionManager, ServerConfig config) {
        this.username = username;
        this.clientSocket = clientSocket;
        this.in = in;
        this.out = out;
        this.dbSocket = dbSocket;
        try {
            this.dbIn = new DataInputStream(dbSocket.getInputStream());
            this.dbOut = new DataOutputStream(dbSocket.getOutputStream());
        } catch (IOException e) {
            System.err.println("[-] Session: Error creating database streams: " + e.getMessage());
        }
        this.sessionManager = sessionManager;
        this.gson = new Gson();
        this.tokenService = new TokenService(config);
    }

    public void interaction(){
        try {
            while (true) {
                String message = in.readUTF();
                option(message);
            }
        } catch (Exception e) {
            System.err.println("[-] Session: Error in interaction: " + e.getMessage());
        }

    }

    public void option(String opcode){
        switch (Opcode.valueOf(opcode)){
            case ADD_CONTACT:
                addContact();
                break;
            case GET_POSSIBLE_CONTACTS:
                getPossibleContacts();
                break;
            case SEND_MESSAGE:
                sendMessage();
                break;
            case VALIDATE_TOKEN:
                validate_token();
                break;
            case SEND_E2E_MESSAGE:
                sendE2eMessage();
                break;
            case GET_MESSAGES:
                getMessages();
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
            case QUIT:
                logoutUser(username);
                break;
            default:
                System.err.println("[-] Session: Invalid opcode, string received: " + opcode);
        }
    }

    private void validate_token() {
        System.out.println("[DEBUG] Validating token");
        try {
            String token = in.readUTF();
            boolean valid = tokenService.validateToken(token);
            System.out.println("[DEBUG] E2E token is valid: " + valid);
            if(valid) {
                out.writeUTF(Opcode.VALID_TOKEN.name());
            }

        }catch(IOException e){
            System.err.println("[-] Session: Error validating token: " + e.getMessage());
        }
    }

    public void addContact(){
        try {
            // Read the new contact from the client
            String newContact = in.readUTF();

            String[] possibleContacts = getPossibleContactsList();

            // Check if the new contact is in the list of possible contacts
            boolean contactExists = Arrays.asList(possibleContacts).contains(newContact);
            if (!contactExists) {
                out.writeUTF(Opcode.ERROR.name());
                System.err.println("[-] Session: Contact does not exist.");
                return;
            }

            // Retrieve the current contacts of the user
            dbOut.writeUTF(Opcode.GET_CONTACTS.name());
            dbOut.writeUTF(username);
            String[] clientContacts = dbIn.readUTF().split("->");

            // Add the new contact to the user's contact list
            StringBuilder newContactsList = new StringBuilder();
            if (clientContacts.length == 0) {
                newContactsList.append(newContact);
            } else {
                newContactsList.append(String.join("->", clientContacts)).append("->").append(newContact);
            }

            // Update the contacts in the database
            dbOut.writeUTF(Opcode.UPDATE_CONTACTS.name());
            dbOut.writeUTF(username);
            dbOut.writeUTF(newContactsList.toString());

            out.writeUTF(Opcode.OK.name());
            System.out.println("[+] Session: Contact added successfully.");
        } catch (Exception e) {
            System.err.println("[-] Session: Error getting contacts: " + e.getMessage());
        }
    }

    private String[] getPossibleContactsList() throws Exception {
        // Retrieve the list of possible contacts from the database
        // In this case, any user
        dbOut.writeUTF(Opcode.GET_USERS.name());
        String[] possibleContacts = dbIn.readUTF().split("->");
        return possibleContacts;
    }

    private void getPossibleContacts() {
        try {
            String[] possibleContacts = getPossibleContactsList();
            if (possibleContacts.length == 0) {
                out.writeUTF(Opcode.NO_USERS.name());
                System.err.println("[-] Session: No users found.");
                return;
            }

            // Send the list of possible contacts to the client
            StringBuilder contactsList = new StringBuilder();
            for (int i = 0; i < possibleContacts.length; i++) {
                if (i > 0) contactsList.append("->");
                contactsList.append(possibleContacts[i]);
            }

            out.writeUTF(contactsList.toString());
        } catch (Exception e) {
            System.err.println("[-] Session: Error getting users: " + e.getMessage());
        }
    }

    private void sendMessage() {
        try {
            // Receive the message from the client
            String serializedMessage = in.readUTF();
            Message message = new Message(serializedMessage);

            message.setSender(username);

            // Insert the message into the database
            dbOut.writeUTF(Opcode.PUT_MESSAGE.name());
            dbOut.writeUTF(message.toString());
            boolean insertSuccess = dbIn.readBoolean();
            if (insertSuccess) {
                out.writeUTF(Opcode.OK.name());
                System.out.println("[+] Session: Message sent successfully.");
            } else {
                out.writeUTF(Opcode.ERROR.name());
                System.err.println("[-] Session: Error sending message.");
            }
        } catch (Exception e) {
            System.err.println("[-] Session: Error sending message: " + e.getMessage());
        }
    }

    private void sendE2eMessage() {
        try {
            // Receive receiver from the client
            String receiver = in.readUTF();

            // Check if receiver is online
            if (!sessionManager.isUserConnected(receiver)) {
                out.writeUTF(Opcode.ERROR.name());
                System.err.println("[-] Session: Receiver is not connected.");
                return;
            }

            // If user is connected, send their INETAddress to the client
            String address = sessionManager.getConnection(receiver).getInetAddress().getHostAddress();
            out.writeUTF(address);

            // Receive status from client
            String status = in.readUTF();
            if (status.equals(Opcode.ERROR.name())) {
                System.err.println("[-] Session: Error sending E2E message.");
                return;
            }
            // Sending authentication token
            String token = tokenService.generateToken(username, receiver);
            out.writeUTF(token);

            // Now the client can connect to the receiver directly
        } catch (IOException e) {
            System.err.println("[-] Session: Error sending E2E message: " + e.getMessage());
        }
    }

    private void getMessages() {
        // Get messages between client and some contact
        try {
            List<String> messages = new ArrayList<>();
            int finalMessageCount = 0;
            // Receive the contact information from the client
            String contact = in.readUTF();
            // Retrieve and send the chat history to the client
            // From requesting user to contact...
            dbOut.writeUTF(Opcode.GET_MESSAGES_FROM_USER_TO_USER.name());
            dbOut.writeUTF(username);
            dbOut.writeUTF(contact);
            int messageCount = dbIn.readInt();
            finalMessageCount += messageCount;
            for (int i = 0; i < messageCount; i++) {
                String messageJson = dbIn.readUTF();
                messages.add(messageJson);
            }
            // ...and vice-versa
            dbOut.writeUTF(Opcode.GET_MESSAGES_FROM_USER_TO_USER.name());
            dbOut.writeUTF(contact);
            dbOut.writeUTF(username);
            messageCount = dbIn.readInt();
            finalMessageCount += messageCount;
            for (int i = 0; i < messageCount; i++) {
                String messageJson = dbIn.readUTF();
                messages.add(messageJson);
            }
            // Send to client
            out.writeInt(finalMessageCount);
            for (String messageJson : messages) {
                out.writeUTF(messageJson);
            }
        } catch (Exception e) {
            System.err.println("[-] Session: Error sending message: " + e.getMessage());
        }
    }

    private boolean sendToRecipient(String username, Message message){
        if(sessionManager.isUserConnected(username)){
            SSLSocket recipientSocket = sessionManager.getConnection(username);
            try {
                DataOutputStream recipientOut = new DataOutputStream(recipientSocket.getOutputStream());
                System.out.println("[DEBUG] JSON message: " + gson.toJson(message));
                recipientOut.writeUTF(gson.toJson(message));
                return true;
            } catch (Exception e) {
                System.err.println("[-] Session: Error sending message to recipient: " + e.getMessage());
                return false;
            }
        }
        return false;
    }
    
    private void getSalt() {
        try {
            dbOut.writeUTF(Opcode.GET_SALT.name());
            dbOut.writeUTF(username);
            out.writeUTF(dbIn.readUTF());
            System.out.println("[+] Session: Salt retrieved successfully.");
        } catch (Exception e) {
            System.err.println("[-] Session: Error getting salt: " + e.getMessage());
        }
    }

    private void updatePubKey() {
        try {
            // Read the new public key from the client
            String pubKey = in.readUTF();

            // Update the public key in the database
            dbOut.writeUTF(Opcode.UPDATE_PUBKEY.name());
            dbOut.writeUTF(username);
            dbOut.writeUTF(pubKey);

            //out.writeUTF(Opcode.OK.name());
            System.out.println("[+] Session: Public key updated successfully.");
        } catch (Exception e) {
            System.err.println("[-] Session: Error updating public key: " + e.getMessage());
        }
    }

    private void getPubKey() {
        try {
            String contact = in.readUTF();

            dbOut.writeUTF(Opcode.GET_PUBKEY.name());
            dbOut.writeUTF(contact);

            out.writeUTF(dbIn.readUTF());
            System.out.println("[+] Session: Public key retrieved successfully.");
        } catch (Exception e) {
            System.err.println("[-] Session: Error getting public key: " + e.getMessage());
        }
    }

    private void updatePrivKey() {
        try {
            // Read the new private key (encrypted) from the client
            String privKey = in.readUTF();

            // Update the public key in the database
            dbOut.writeUTF(Opcode.UPDATE_PRIVKEY.name());
            dbOut.writeUTF(username);
            dbOut.writeUTF(privKey);

            //out.writeUTF(Opcode.OK.name());
            System.out.println("[+] Session: Private key updated successfully.");
        } catch (Exception e) {
            System.err.println("[-] Session: Error updating private key: " + e.getMessage());
        }
    }

    private void logoutUser(String username){
        sessionManager.removeConnection(username);
    }

}


