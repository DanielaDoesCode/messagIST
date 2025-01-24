# iptable Rules

## Client
```bash
# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback interface - for clients on the same IP to connect
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow traffic to the server
iptables -A OUTPUT -d SERVER_IP -p tcp --dport SERVER_PORT -j ACCEPT
iptables -A INPUT -s SERVER_IP -p tcp --sport SERVER_PORT -j ACCEPT

# Allow outgoing traffic to client for E2E Communication
iptables -A OUTPUT -d CLIENT_IP -p tcp --dport E2E_PORT -j ACCEPT
iptables -A INPUT -s CLIENT_IP -p tcp --sport E2E_PORT -j ACCEPT

# Allow incoming traffic from client for E2E Communication
iptables -A INPUT -s CLIENT_IP -p tcp --dport E2E_PORT -j ACCEPT
iptables -A OUTPUT -d CLIENT_IP -p tcp --sport E2E_PORT -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```
## Server
```bash
# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow incoming traffic from the client on specific port
iptables -A INPUT -s CLIENT1_IP -p tcp --dport SERVER_PORT -j ACCEPT
iptables -A OUTPUT -d CLIENT1_IP -p tcp --sport SERVER_PORT -j ACCEPT

# Allow incoming traffic from the client on specific port (in case we have the 4 machine configuration)
iptables -A INPUT -s CLIENT1_IP -p tcp --dport SERVER_PORT -j ACCEPT
iptables -A OUTPUT -d CLIENT1_IP -p tcp --sport SERVER_PORT -j ACCEPT

# Allow outgoing traffic to the DatabaseServer
iptables -A OUTPUT -d DATABASE_IP -p tcp --dport DATABASE_PORT -j ACCEPT
iptables -A INPUT -s DATABASE_IP -p tcp --sport DATABASE_PORT -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```
## Database
```bash
# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow incoming traffic from the Server
iptables -A INPUT -s SERVER_IP -p tcp --dport DATABASE_PORT -j ACCEPT
iptables -A OUTPUT -d SERVER_IP -p tcp --sport DATABASE_PORT -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
```
