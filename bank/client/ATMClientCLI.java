// ATMClientCLI.java
package bank.client;

import bank.shared.CryptoUtil;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Scanner;

public class ATMClientCLI {
    private static Socket socket;
    private static SecretKey encKey;
    private static SecretKey macKey;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.println("Welcome to CLI ATM Client");
            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            System.out.print("Enter password: ");
            String password = scanner.nextLine();
            System.out.print("Register or Login? (r/l): ");
            String action = scanner.nextLine().equalsIgnoreCase("r") ? "register" : "login";

            socket = new Socket("localhost", 5000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            writer.println(username + "::" + password + "::" + action);
            writer.flush();
            System.out.println("Client sent login request.");

            String reply = reader.readLine();
            System.out.println("Client received reply: " + reply);

            if (reply == null || reply.startsWith("ERROR")) {
                System.out.println("[SERVER] " + reply);
                return;
            } else if (reply.equals("REGISTERED")) {
                System.out.println("[SERVER] Registered. Please login again.");
                return;
            } else if (!reply.equals("READY_FOR_KEY_EXCHANGE")) {
                System.out.println("Unexpected response from server: " + reply);
                return;
            }

            // Receive nonce1
            String nonce1Base64 = reader.readLine();
            byte[] nonce1 = Base64.getDecoder().decode(nonce1Base64);
            System.out.println("Client received nonce1 from server.");

            // Send nonce2
            byte[] nonce2 = CryptoUtil.generateNonce();
            String nonce2Base64 = Base64.getEncoder().encodeToString(nonce2);
            writer.println("NONCE2:" + nonce2Base64);
            writer.flush();
            System.out.println("Client sent nonce2.");

            byte[] masterSecret = CryptoUtil.hmac(CryptoUtil.SHARED_SECRET, CryptoUtil.concat(nonce1, nonce2));
            encKey = CryptoUtil.deriveKey(masterSecret, "ENCRYPT");
            macKey = CryptoUtil.deriveKey(masterSecret, "MAC");

            String authResp = reader.readLine();
            System.out.println("Client received auth response: " + authResp);
            if (!"AUTH_SUCCESS".equals(authResp)) {
                System.out.println("Authentication failed.");
                return;
            }
            System.out.println("Authenticated successfully!\n");

            while (true) {
                System.out.print("Enter command (deposit <amt> / withdraw <amt> / balance / exit): ");
                String inputLine = scanner.nextLine();
                if (inputLine.equalsIgnoreCase("exit")) break;

                String[] parts = inputLine.trim().split(" ");
                String command = parts[0];
                String payload = command;
                if (parts.length > 1) payload += ":" + parts[1];

                String encrypted = CryptoUtil.encrypt(payload, encKey);
                String mac = CryptoUtil.generateMAC(encrypted, macKey);
                writer.println(encrypted + "::" + mac);

                String[] responseParts = reader.readLine().split("::");
                if (!CryptoUtil.verifyMAC(responseParts[0], responseParts[1], macKey)) {
                    System.out.println("[ERROR] Invalid MAC from server.");
                    continue;
                }
                String decrypted = CryptoUtil.decrypt(responseParts[0], encKey);
                System.out.println("[SERVER]: " + decrypted);
            }

            socket.close();
            System.out.println("Connection closed.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
