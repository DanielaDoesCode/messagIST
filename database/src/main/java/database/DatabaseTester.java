package database;

import java.util.Scanner;

public class DatabaseTester {
    public static void main(String[] args){
        DatabaseConnector db = new DatabaseConnector();
        //db.insertMessage("Hello, World!", "Alice", "Bob");
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter a message: ");
        String message = sc.nextLine();
        System.out.println("Enter the sender: ");
        String sender = sc.nextLine();
        System.out.println("Enter the receiver: ");
        String receiver = sc.nextLine();
        //db.insertMessage(message, sender, receiver);
        //db.findMessage(message);
    }
}
