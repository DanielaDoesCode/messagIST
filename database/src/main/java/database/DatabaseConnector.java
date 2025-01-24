package database;

import com.google.gson.Gson;
import message.Message;

import java.sql.*;
import java.sql.SQLException;
import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ArrayList;

public final class DatabaseConnector {
    //using duckdb as a database due to its simplicity of installation and use
    private Connection conn;
    private Gson gson;

    public DatabaseConnector() {
        try {
            conn = DriverManager.getConnection("jdbc:duckdb:"); //in-memory database
            gson = new Gson();
        } catch (SQLException e) {
            System.err.println("Connection to database failed: " + e.getMessage());
        }

        startDatabase();
    }

    public void startDatabase() {
        try {
            Statement stmt = conn.createStatement();
            //creating a table for the messages
            stmt.execute("CREATE TABLE messages (" +
                    "content TEXT, " +
                    "sender TEXT, " +
                    "receiver TEXT, " +
                    "timestamp TIMESTAMP" +
                    ")");
            System.out.println("Table 'messages' created successfully.");

            //creating a table for the clients
            stmt.execute("CREATE TABLE clients (" +
                    "name TEXT, " +
                    "password TEXT, " +
                    "salt TEXT, " +
                    "contacts TEXT, " +
                    "pubkey TEXT, " +
                    "privkey TEXT, " + // private key encrypted with secret key, generated with recovery password
                    ")");
            System.out.println("Table 'clients' created successfully.");
        } catch (SQLException e) {
            System.err.println("[-] Database: Error creating table: " + e.getMessage());
        }
    }

    public boolean insertMessage(Message message) {
        try {
            String messageJson = message.toString();
            String query = "INSERT INTO messages (content, sender, receiver, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, messageJson);
            pstmt.setString(2, message.getSender());
            pstmt.setString(3, message.getReceiver());
            pstmt.executeUpdate();
            System.out.println("Message inserted successfully!");
            return true;
        } catch (SQLException e) {
            System.err.println("[-] Database: Error inserting message: " + e.getMessage());
            return false;
        }
    }

    public Message findMessage(String content) {
        try {
            String query = "SELECT content FROM messages WHERE content LIKE ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, "%" + content + "%");
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String messageJson = rs.getString("content");
                return new Message(messageJson);
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error finding message: " + e.getMessage());
        }
        return null;
    }

    public List<String> getDistinctReceivers(String sender) {
        List<String> receivers = new ArrayList<>();
        try {
            String query = "SELECT DISTINCT receiver FROM messages WHERE sender = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, sender);
            ResultSet resultSet = pstmt.executeQuery();

            while (resultSet.next()) {
                receivers.add(resultSet.getString("receiver"));
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error retrieving distinct receivers: " + e.getMessage());
        }
        return receivers;
    }

    public boolean insertClient(String name, String password, String salt, String contacts) {
        try {
            String query = "INSERT INTO clients (name, password, salt, contacts) VALUES (?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(query);
            stmt.setString(1, name);
            stmt.setString(2, password);
            stmt.setString(3, salt);
            stmt.setString(4, contacts);
            stmt.execute();
            System.out.println("Client inserted successfully!");
            return true;
        } catch (SQLException e) {
            System.err.println("[-] Database: Error inserting message: " + e.getMessage());
            return false;
        }
    }

    public boolean updateContacts(String username, String newContacts) {
        try {
            String query = "UPDATE clients SET contacts = ? WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, newContacts);
            pstmt.setString(2, username);

            int rowsUpdated = pstmt.executeUpdate();

            // Check if any rows were updated
            if (rowsUpdated > 0) {
                System.out.println("Contacts updated successfully for user: " + username);
                return true;
            } else {
                System.err.println("No user found with the username: " + username);
                return false;
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error updating contacts: " + e.getMessage());
            return false;
        }
    }

    public String getContacts(String username) {
        try {
            String query = "SELECT contacts FROM clients WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username); // Set the username parameter

            ResultSet rs = pstmt.executeQuery();

            // Check if a result was found
            if (rs.next()) {
                String contacts = rs.getString("contacts"); // Retrieve the contacts column
                System.out.println("Contacts string: " + contacts);
                System.out.println("Contacts retrieved for user: " + username);
                return contacts; // Return the contacts
            } else {
                System.err.println("No user found with the username: " + username);
                return null;
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error retrieving contacts: " + e.getMessage());
            return null;
        }
    }

    public boolean deleteContact(String username, String contact) {
        try {
            String query = "SELECT contacts FROM clients WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String contacts = rs.getString("contacts");
                String[] contactsArray = contacts.split("->");
                StringBuilder newContacts = new StringBuilder();
                for (String c : contactsArray) {
                    if (!c.equals(contact)) {
                        newContacts.append(c).append("->");
                    }
                }
                if (newContacts.length() > 0) {
                    newContacts.deleteCharAt(newContacts.length() - 1);
                }
                return updateContacts(username, newContacts.toString());
            } else {
                System.err.println("No user found with the username: " + username);
                return false;
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error deleting contact: " + e.getMessage());
            return false;
        }
    }

    public List<Message> getAllMessagesfromUserToUser(String sender, String receiver) {
        List<Message> messages = new ArrayList<>();
        try {
            String query = "SELECT content FROM messages WHERE sender = ? AND receiver = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, sender);
            pstmt.setString(2, receiver);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String messageJson = rs.getString("content");
                Message message = new Message(messageJson);
                messages.add(message);
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error fetching messages: " + e.getMessage());
        }
        return messages;
    }

    public String getClientSalt(String name) {
        String salt = "";
        try {
            String query = "SELECT salt FROM clients WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, name);
            ResultSet rs = pstmt.executeQuery();

            // Check if the result set contains data
            if (rs.next()) {
                salt = rs.getString("salt");
                System.out.println("Salt: " + salt);
            } else {
                System.out.println("Client not found!");
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error fetching client salt value: " + e.getMessage());
        }
        return salt;
    }

    public void getClientCredentials(String name) {
        try {
            Statement stmt = conn.createStatement();
            String query = "SELECT password, salt FROM clients WHERE name = '" + name + "'";
            ResultSet rs = stmt.executeQuery(query);

            // Check if the result set contains data
            if (rs.next()) {
                String password = rs.getString("password");
                String salt = rs.getString("salt");
                System.out.println("Password: " + password);
                System.out.println("Salt: " + salt);
            } else {
                System.out.println("Client not found!");
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error fetching client credentials: " + e.getMessage());
        }
    }

    public boolean checkUser(String username){
        String query = "SELECT COUNT(*) AS count FROM clients WHERE name = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                int count = rs.getInt("count");
                return count > 0;
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error checking if user exists: " + e.getMessage());
        }
        return false;
    }

    public boolean checkCredentials(String username, String password){
        String query = "SELECT password, salt FROM clients WHERE name = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String dbPassword = rs.getString("password");
                String salt = rs.getString("salt");
                String saltedPassword = salt + password;
                return dbPassword.equals(saltedPassword);
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error checking credentials: " + e.getMessage());
        }
        return false;
    }

    // Backup the database to persistent storage
    public void backupDatabase(String backupDir) {
        try {
            File dir = new File(backupDir);
            if (!dir.exists()) {
                if (dir.mkdirs()) {
                    System.out.println("Backup directory created: " + backupDir);
                } else {
                    System.err.println("Failed to create backup directory.");
                    return;
                }
            }

            Statement stmt = conn.createStatement();

            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
            String timestamp = LocalDateTime.now().format(formatter);

            // Export the `messages` table to a CSV file
            String messagesBackupPath = backupDir + "/messages_backup_" + timestamp + ".csv";
            stmt.execute("COPY messages TO '" + messagesBackupPath + "' (FORMAT CSV, HEADER)");
            System.out.println("Messages table backed up to: " + messagesBackupPath);

            // Export the `clients` table to a CSV file
            String clientsBackupPath = backupDir + "/clients_backup_" + timestamp + ".csv";
            stmt.execute("COPY clients TO '" + clientsBackupPath + "' (FORMAT CSV, HEADER)");
            System.out.println("Clients table backed up to: " + clientsBackupPath);
        } catch (SQLException e) {
            System.err.println("[-] Database: Error backing up database: " + e.getMessage());
        }
    }

    public String[] getAllClientsUsername() {
        try {
            String query = "SELECT name FROM clients";
            PreparedStatement pstmt = conn.prepareStatement(query);
            ResultSet rs = pstmt.executeQuery();
            int count = 0;
            while (rs.next()) {
                count++;
            }
            String[] usernames = new String[count];
            rs = pstmt.executeQuery();
            int i = 0;
            while (rs.next()) {
                usernames[i] = rs.getString("name");
                i++;
            }
            return usernames;
        } catch (SQLException e) {
            System.err.println("[-] Database: Error fetching all clients' usernames: " + e.getMessage());
            return null;
        }
    }

    public boolean setClientPubKey(String username, String pubKey) {
        try {
            String query = "UPDATE clients SET pubkey = ? WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, pubKey);
            pstmt.setString(2, username);

            int rowsUpdated = pstmt.executeUpdate();

            // Check if any rows were updated
            if (rowsUpdated > 0) {
                System.out.println("Public key updated successfully for user: " + username);
                return true;
            } else {
                System.err.println("No user found with the username: " + username);
                return false;
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error updating public key: " + e.getMessage());
            return false;
        }
    }

    public String getClientPubKey(String username) {
        String pubKey = "";
        try {
            String query = "SELECT pubkey FROM clients WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            // Check if the result set contains data
            if (rs.next()) {
                pubKey = rs.getString("pubkey");
                System.out.println("Public key: " + pubKey);
            } else {
                System.out.println("Client not found!");
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error fetching client public key: " + e.getMessage());
        }
        return pubKey;
    }

    public boolean setClientPrivKey(String username, String privKey) {
        try {
            String query = "UPDATE clients SET privkey = ? WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, privKey);
            pstmt.setString(2, username);

            int rowsUpdated = pstmt.executeUpdate();

            // Check if any rows were updated
            if (rowsUpdated > 0) {
                System.out.println("Private key updated successfully for user: " + username);
                return true;
            } else {
                System.err.println("No user found with the username: " + username);
                return false;
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error updating private key: " + e.getMessage());
            return false;
        }
    }

    public String getClientPrivKey(String username) {
        String privKey = "";
        try {
            String query = "SELECT privkey FROM clients WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            // Check if the result set contains data
            if (rs.next()) {
                privKey = rs.getString("privkey");
                System.out.println("Private key (encrypted): " + privKey);
            } else {
                System.out.println("Client not found!");
            }
        } catch (SQLException e) {
            System.err.println("[-] Database: Error fetching client private key: " + e.getMessage());
        }
        return privKey;
    }
}

