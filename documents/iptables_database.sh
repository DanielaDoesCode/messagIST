#!/bin/bash

# Variables
SERVER_IP="192.168.1.254"
DATABASE_PORT="12345"

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

# Allow incoming traffic from the server
iptables -A INPUT -s $SERVER_IP -p tcp --dport $DATABASE_PORT -j ACCEPT
iptables -A OUTPUT -d $SERVER_IP -p tcp --sport $DATABASE_PORT -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP
