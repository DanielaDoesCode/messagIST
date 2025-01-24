package client;

import message.Message;
import message.Opcode;

import java.io.*;
import java.net.Socket;
import java.sql.Driver;

// Handler for each E2E communication
class E2ECommunicationHandler implements Runnable {
    private final Socket clientSocket;
    private final ClientConfig config;
    private final ClientLocalStorage localStorage;
    private final DataOutputStream serverOut;
    private final DataInputStream serverIn;
    public E2ECommunicationHandler(Socket clientSocket, ClientConfig config, ClientLocalStorage localStorage, DataOutputStream serverOut, DataInputStream serverIn) {
        this.clientSocket = clientSocket;
        this.config = config;
        this.localStorage = localStorage;
        this.serverOut = serverOut;
        this.serverIn = serverIn;
    }

    @Override
    public void run() {
        try{
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            System.out.println("Handling E2E communication with: " + clientSocket.getInetAddress());

            //Receive token
            String token = in.readUTF();
            System.out.println("Received token: " + token);

            //Request the server to validate it
            serverOut.writeUTF(Opcode.VALIDATE_TOKEN.name());
            System.out.println("Requesting server to validate token");
            serverOut.writeUTF(token);
            System.out.println("Sent token to server");

            //Receive the response
            String response = serverIn.readUTF();
            System.out.println("Received response from server: " + response);
            if(response.equals(Opcode.INVALID_TOKEN.name())){
                System.out.println("Token is invalid. Closing connection.");
                String messageString = in.readUTF(); //just so the clients don't get stuck, but we don't do anything with it
                out.writeUTF("NO-OK");
                clientSocket.close();
                return;
            }else{
                String messageString = in.readUTF();
                out.writeUTF("OK"); //send ok to sender

                //Storing in the local database
                Message message = new Message(messageString);
                localStorage.insertMessages(message);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}