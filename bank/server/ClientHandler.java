// ClientHandler.java
package bank.server;

import bank.shared.*;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.Base64;

public class ClientHandler implements Runnable {
    private final Socket socket;
    private final Map<String, String> users;
    private final Map<String, Double> balances;
    private BufferedReader in;
    private PrintWriter out;
    private SecretKey encKey;
    private SecretKey macKey;
    private String username;

    public ClientHandler(Socket socket, Map<String, String> users, Map<String, Double> balances) {
        this.socket = socket;
        this.users = users;
        this.balances = balances;
    }

    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            System.out.println("[SERVER] ClientHandler thread started");

            String request = in.readLine();
            if (request == null) {
                System.out.println("[SERVER] Client disconnected before sending login/registration.");
                return;
            }

            System.out.println("[SERVER] Received request: " + request);
            String[] parts = request.split("::");
            username = parts[0];
            String password = parts[1];
            String action = parts[2];

            if (action.equals("register")) {
                if (users.containsKey(username)) {
                    out.println("ERROR: User exists");
                    System.out.println("[SERVER] Registration failed. User exists.");
                    return;
                }
                users.put(username, CryptoUtil.hashPassword(password));
                balances.put(username, 0.0);
                out.println("REGISTERED");
                System.out.println("[SERVER] User registered successfully: " + username);
                return;
            } else if (!users.containsKey(username) ||
                    !users.get(username).equals(CryptoUtil.hashPassword(password))) {
                out.println("ERROR: Invalid login");
                System.out.println("[SERVER] Invalid login for user: " + username);
                return;
            }

            System.out.println("[SERVER] Starting key exchange for: " + username);
            out.println("READY_FOR_KEY_EXCHANGE");

            byte[] nonce1 = CryptoUtil.generateNonce();
            String nonce1Base64 = Base64.getEncoder().encodeToString(nonce1);
            out.println(nonce1Base64);
            out.flush();
            System.out.println("[SERVER] Sent nonce1 to " + username);

            String nonce2Line = in.readLine();
            if (nonce2Line == null || !nonce2Line.startsWith("NONCE2:")) {
                System.out.println("[SERVER] Did not receive proper nonce2 response.");
                return;
            }
            byte[] nonce2 = Base64.getDecoder().decode(nonce2Line.substring(7));
            System.out.println("[SERVER] Received nonce2 from " + username);

            byte[] masterSecret = CryptoUtil.hmac(CryptoUtil.SHARED_SECRET, CryptoUtil.concat(nonce1, nonce2));
            encKey = CryptoUtil.deriveKey(masterSecret, "ENCRYPT");
            macKey = CryptoUtil.deriveKey(masterSecret, "MAC");

            out.println("AUTH_SUCCESS");
            System.out.println("[SERVER] Sent AUTH_SUCCESS to " + username);

            String encryptedLine;
            while ((encryptedLine = in.readLine()) != null) {
                System.out.println("[SERVER] Received encrypted command from " + username);
                String[] parts2 = encryptedLine.split("::");
                String encryptedPayload = parts2[0];
                String mac = parts2[1];

                if (!CryptoUtil.verifyMAC(encryptedPayload, mac, macKey)) {
                    out.println("MAC_ERROR");
                    System.out.println("[SERVER] MAC error for user: " + username);
                    continue;
                }

                String commandPayload = CryptoUtil.decrypt(encryptedPayload, encKey);
                String[] cmdParts = commandPayload.split(":");
                String command = cmdParts[0];
                double amount = cmdParts.length > 1 ? Double.parseDouble(cmdParts[1]) : 0.0;

                System.out.println("[SERVER] " + username + " requested: " + command + (cmdParts.length > 1 ? " " + amount : ""));

                String response;
                synchronized (balances) {
                    if (command.equals("deposit")) {
                        balances.put(username, balances.get(username) + amount);
                        response = "Deposited " + amount + ". New balance: " + balances.get(username);
                    } else if (command.equals("withdraw")) {
                        if (balances.get(username) < amount) {
                            response = "Insufficient funds.";
                        } else {
                            balances.put(username, balances.get(username) - amount);
                            response = "Withdrew " + amount + ". New balance: " + balances.get(username);
                        }
                    } else if (command.equals("balance")) {
                        response = "Current balance: " + balances.get(username);
                    } else {
                        response = "Invalid command.";
                    }
                }

                String encryptedResp = CryptoUtil.encrypt(response, encKey);
                String responseMac = CryptoUtil.generateMAC(encryptedResp, macKey);
                out.println(encryptedResp + "::" + responseMac);

                AuditLogger.log(username + " | " + command + " | " + new Date());
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("[SERVER] Exception in ClientHandler: " + e.getMessage());
        }
    }
}
