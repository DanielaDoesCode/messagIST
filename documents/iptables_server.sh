#!/bin/bash

# Variables
SERVER_PORT="9999"
DATABASE_IP="192.168.1.1"
DATABASE_PORT="12345"
CLIENT_IP="192.168.0.0/24"

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

# Allow incoming traffic from the client
iptables -A INPUT -s $CLIENT_IP -p tcp --dport $SERVER_PORT -j ACCEPT
iptables -A OUTPUT -d $CLIENT_IP -p tcp --sport $SERVER_PORT -j ACCEPT

# Allow outgoing traffic to the database (replace DATABASE_IP and DATABASE_PORT)
iptables -A OUTPUT -d $DATABASE_IP -p tcp --dport $DATABASE_PORT -j ACCEPT
iptables -A INPUT -s $DATABASE_IP -p tcp --sport $DATABASE_PORT -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
