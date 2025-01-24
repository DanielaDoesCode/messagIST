package client;

import com.google.gson.Gson;
import message.Message;

import java.io.File;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class ClientLocalStorage {
    private Connection conn;
    private Gson gson;

    public ClientLocalStorage() {
        try{
            conn = DriverManager.getConnection("jdbc:duckdb:");
            gson = new Gson();
        }catch(SQLException e){
            System.err.println("Connection to local Database failed! " + e.getMessage());
        }
        startDatabase();
    }

    public void startDatabase(){
        try{
            Statement stmt = conn.createStatement();
            //creating table for the messages
            stmt.execute("CREATE TABLE E2Emessages (" +
                    "content TEXT, " +
                    "sender TEXT, " +
                    "receiver TEXT, " +
                    "timestamp TIMESTAMP" +
                    ")");
            System.out.println("Table 'E2Emessages' created successfully.");
        }catch(SQLException e){
            System.err.println("[-] Client Database: Error creating table 'E2Emessages': " + e.getMessage());
        }
    }


    public boolean insertMessages(Message message){
        try {
            String messageJson = message.toString();
            String query = "INSERT INTO E2Emessages (content, sender, receiver, timestamp) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
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

    public List<Message> getAllMessagesfromUserToUser(String sender, String receiver) {
        List<Message> messages = new ArrayList<>();
        try {
            String query = "SELECT content FROM E2Emessages WHERE sender = ? AND receiver = ?";
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
            stmt.execute("COPY E2Emessages TO '" + messagesBackupPath + "' (FORMAT CSV, HEADER)");
            System.out.println("Messages table backed up to: " + messagesBackupPath);

        } catch (SQLException e) {
            System.err.println("[-] Client Database: Error backing up database: " + e.getMessage());
        }
    }
}
