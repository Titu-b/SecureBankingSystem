/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bank.tools;

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

public class AuditLogDecryptor {
    private static final String LOG_FILE = "audit.log.enc";
    private static final byte[] LOG_KEY = "encryptionkey123".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new FileReader(LOG_FILE))) {
            String line;
            System.out.println("--- Decrypted Audit Log ---\n");
            while ((line = reader.readLine()) != null) {
                try {
                    String decrypted = decrypt(line);
                    System.out.println(decrypted);
                } catch (Exception e) {
                    System.out.println("[ERROR] Failed to decrypt a line: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String decrypt(String encoded) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encoded);
        byte[] iv = Arrays.copyOfRange(combined, 0, 12);
        byte[] cipherText = Arrays.copyOfRange(combined, 12, combined.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec keySpec = new SecretKeySpec(LOG_KEY, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}

