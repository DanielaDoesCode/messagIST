package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class E2EConnectionListener implements Runnable {
    private final ClientLocalStorage localStorage;
    private final DataOutputStream out;
    private final DataInputStream in;
    public E2EConnectionListener(ClientLocalStorage localStorage, DataOutputStream serverOut, DataInputStream serverIn) {
        this.localStorage = localStorage;
        this.out = serverOut;
        this.in = serverIn;
    }
    @Override
    public void run() {
        try {
            ClientConfig config = new ClientConfig();
            ServerSocket E2eSocket = new ServerSocket(config.E2E_PORT);
            System.out.println("E2E Server Started");
            while (true) {
                Socket socket = E2eSocket.accept();
                System.out.println("E2E Client Connected");
                new Thread(new E2ECommunicationHandler(socket, config, localStorage, out, in)).start();
            }
        } catch (IOException e) {
            System.err.println("E2E Connection Failed");
        }
    }
}
