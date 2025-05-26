# Secure Banking System

A secure client-server banking simulation developed in Java using TCP sockets, multithreading, and cryptographic techniques. This project demonstrates fundamental concepts in network security, including symmetric encryption, message authentication, session key derivation, and secure logging.

## Features

- Secure ATM-server communication over TCP sockets
- AES-128 encryption for message confidentiality
- HMAC-SHA256 for message integrity and authentication
- Custom key exchange protocol using nonces and pre-shared keys
- GUI and CLI-based ATM clients
- Encrypted audit logging and standalone decryptor utility
- Multi-threaded server handling concurrent clients

## Project Structure
/bank/

├── client/ # ATM clients: GUI and CLI

│ ├── ATMClient.java

│ ├── ATMClientCLI.java

│ └── ATMGUI.java

├── server/ # Server-side logic

│ ├── BankServer.java

│ ├── ClientHandler.java

│ └── AuditLogger.java

├── shared/ # Shared cryptographic utilities

│ └── CryptoUtil.java

└── tools/ # Audit log decryption tool

└── AuditLogDecryptor.java


## Technologies Used

- Java (JDK 8+)
- NetBeans IDE
- TCP Sockets
- Java Swing (GUI)
- AES-128 encryption (javax.crypto)
- HMAC-SHA256 (javax.crypto.Mac)
- File I/O and multithreading

## How It Works

1. **Initialization**  
   - Clients and server share a pre-distributed secret key.
   - Clients generate a random nonce and start a key exchange protocol.

2. **Session Key Derivation**  
   - Session keys are derived using the pre-shared key and exchanged nonces.
   - AES and HMAC keys are then separated from the session material.

3. **Secure Communication**  
   - All messages between the ATM and bank server are encrypted using AES.
   - Each message is authenticated with HMAC-SHA256 to ensure integrity.

4. **Audit Logging**  
   - All transactions are logged in an encrypted audit file by the server.
   - A decryptor utility allows authorized staff to securely view logs.

## How to Run

1. Open the project in NetBeans (or your preferred Java IDE).
2. Run `BankServer.java` to start the server.
3. Run either:
   - `ATMClientCLI.java` for the command-line interface, or
   - `ATMGUI.java` for the graphical interface.
4. Use the `AuditLogDecryptor.java` tool to view encrypted logs.

## Authors

- Tala Baaj  
  Final-year Computer Engineering student at Toronto Metropolitan University  
  Project developed for COE817: Network Security, Winter 2025

