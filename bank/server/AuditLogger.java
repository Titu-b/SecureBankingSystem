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


import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.Base64;

public class AuditLogger {
    private static final String LOG_FILE = "audit.log.enc";
    private static final byte[] LOG_KEY = "encryptionkey123".getBytes(StandardCharsets.UTF_8);

    public static void log(String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            SecretKeySpec keySpec = new SecretKeySpec(LOG_KEY, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(iv);
            outputStream.write(encrypted);

            String encoded = Base64.getEncoder().encodeToString(outputStream.toByteArray());
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
                writer.write(encoded);
                writer.newLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

