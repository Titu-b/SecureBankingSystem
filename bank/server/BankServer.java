/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bank.server;

/**
 *
 * @author Munevver
 */

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class BankServer {
    private static final int PORT = 5000;
    private static final Map<String, String> users = new ConcurrentHashMap<>();
    private static final Map<String, Double> balances = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("[SERVER] Bank server started on port " + PORT);

        ExecutorService pool = Executors.newFixedThreadPool(10);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("[SERVER] Client connected: " + clientSocket.getInetAddress());
            pool.execute(new ClientHandler(clientSocket, users, balances));
        }
    }
}

