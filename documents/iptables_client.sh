#!/bin/bash

# Variables
SERVER_IP="192.168.0.10"
SERVER_PORT="9999"
CLIENT_IP="192.168.0.0/24"
E2E_PORT="7777"

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

# Allow outgoing traffic to the server
iptables -A OUTPUT -d $SERVER_IP -p tcp --dport $SERVER_PORT -j ACCEPT
iptables -A INPUT -s $SERVER_IP -p tcp --sport $SERVER_PORT -j ACCEPT

# Allow outgoing traffic to other client
iptables -A OUTPUT -d $CLIENT_IP -p tcp --dport $E2E_PORT -j ACCEPT
iptables -A INPUT -s $CLIENT_IP -p tcp --sport $E2E_PORT -j ACCEPT

# Allow incoming traffic from other client
iptables -A INPUT -s $CLIENT_IP -p tcp --dport $E2E_PORT -j ACCEPT
iptables -A OUTPUT -d $CLIENT_IP -p tcp --sport $E2E_PORT -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
