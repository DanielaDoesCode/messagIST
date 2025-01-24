package server;

import javax.net.ssl.SSLSocket;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    private ConcurrentHashMap<String, SSLSocket> connections;

    public SessionManager() {
        connections = new ConcurrentHashMap<>();
    }

    public synchronized void addConnection(String username, SSLSocket socket) {
        connections.put(username, socket);
    }

    public synchronized SSLSocket getConnection(String username) {
        return connections.get(username);
    }

    public synchronized void removeConnection(String username) {
        connections.remove(username);
    }

    public synchronized boolean isUserConnected(String username) {
        return connections.containsKey(username);
    }

}
