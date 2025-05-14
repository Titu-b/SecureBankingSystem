// ATMClient.java
package bank.client;

import bank.shared.CryptoUtil;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class ATMClient extends JFrame {
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTextArea outputArea;
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private SecretKey encKey;
    private SecretKey macKey;
    private String username;
    private JButton depositBtn, withdrawBtn, balanceBtn;

    public ATMClient() {
        setTitle("Secure ATM Client");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel loginPanel = new JPanel(new GridLayout(3, 2));
        loginPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        loginPanel.add(usernameField);
        loginPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        loginPanel.add(passwordField);

        JButton loginButton = new JButton("Login");
        JButton registerButton = new JButton("Register");
        loginPanel.add(loginButton);
        loginPanel.add(registerButton);

        add(loginPanel, BorderLayout.NORTH);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        add(new JScrollPane(outputArea), BorderLayout.CENTER);

        JPanel actionPanel = new JPanel();
        depositBtn = new JButton("Deposit");
        withdrawBtn = new JButton("Withdraw");
        balanceBtn = new JButton("Balance");
        depositBtn.setEnabled(false);
        withdrawBtn.setEnabled(false);
        balanceBtn.setEnabled(false);

        actionPanel.add(depositBtn);
        actionPanel.add(withdrawBtn);
        actionPanel.add(balanceBtn);
        add(actionPanel, BorderLayout.SOUTH);

        loginButton.addActionListener(e -> connectAndLogin("login"));
        registerButton.addActionListener(e -> connectAndLogin("register"));
        depositBtn.addActionListener(e -> handleCommand("deposit"));
        withdrawBtn.addActionListener(e -> handleCommand("withdraw"));
        balanceBtn.addActionListener(e -> handleCommand("balance"));

        setVisible(true);
    }

    private void connectAndLogin(String action) {
        disableTransactionButtons();

        try {
            if (socket != null && !socket.isClosed()) socket.close();
            socket = new Socket("localhost", 5000);

            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword()).trim();
            if (username.isEmpty() || password.isEmpty()) {
                outputArea.append("Username and password cannot be empty.\n");
                return;
            }

            out.println(username + "::" + password + "::" + action);
            out.flush();
            outputArea.append("Client sent login request.\n");

            String reply = in.readLine();
            outputArea.append("Client received reply: " + reply + "\n");

            if (reply == null || reply.startsWith("ERROR")) {
                outputArea.append("[SERVER] " + reply + "\n");
                return;
            } else if (reply.equals("REGISTERED")) {
                outputArea.append("[SERVER] Registered. Please login again.\n");
                return;
            } else if (!reply.equals("READY_FOR_KEY_EXCHANGE")) {
                outputArea.append("Unexpected response from server: " + reply + "\n");
                return;
            }

            String nonce1Base64 = in.readLine();
            byte[] nonce1 = Base64.getDecoder().decode(nonce1Base64);
            outputArea.append("Client received nonce1 from server.\n");

            byte[] nonce2 = CryptoUtil.generateNonce();
            String nonce2Base64 = Base64.getEncoder().encodeToString(nonce2);
            out.println("NONCE2:" + nonce2Base64);
            out.flush();
            outputArea.append("Client sent nonce2.\n");

            byte[] masterSecret = CryptoUtil.hmac(CryptoUtil.SHARED_SECRET, CryptoUtil.concat(nonce1, nonce2));
            encKey = CryptoUtil.deriveKey(masterSecret, "ENCRYPT");
            macKey = CryptoUtil.deriveKey(masterSecret, "MAC");

            String authStatus = in.readLine();
            outputArea.append("Client received auth response: " + authStatus + "\n");

            if ("AUTH_SUCCESS".equals(authStatus)) {
                outputArea.append("Authenticated successfully!\n");
                enableTransactionButtons();
            } else {
                outputArea.append("Authentication failed.\n");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            outputArea.append("Connection error.\n");
        }
    }

    private void handleCommand(String command) {
        try {
            if (encKey == null || macKey == null) {
                outputArea.append("Not authenticated. Please login first.\n");
                return;
            }

            String message = command;
            if (!command.equals("balance")) {
                String input = JOptionPane.showInputDialog("Enter amount:");
                if (input == null || input.isEmpty()) return;
                message = command + ":" + input.trim();
            }

            String encPayload = CryptoUtil.encrypt(message, encKey);
            String mac = CryptoUtil.generateMAC(encPayload, macKey);
            out.println(encPayload + "::" + mac);

            String[] resp = in.readLine().split("::");
            if (!CryptoUtil.verifyMAC(resp[0], resp[1], macKey)) {
                outputArea.append("Invalid MAC detected.\n");
                return;
            }
            String reply = CryptoUtil.decrypt(resp[0], encKey);
            outputArea.append(reply + "\n");

        } catch (Exception ex) {
            ex.printStackTrace();
            outputArea.append("Error processing transaction.\n");
        }
    }

    private void enableTransactionButtons() {
        depositBtn.setEnabled(true);
        withdrawBtn.setEnabled(true);
        balanceBtn.setEnabled(true);
    }

    private void disableTransactionButtons() {
        depositBtn.setEnabled(false);
        withdrawBtn.setEnabled(false);
        balanceBtn.setEnabled(false);
    }

    public static void main(String[] args) {
        new ATMClient();
    }
}