/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bank.shared;

/**
 *
 * @author Munevver
 */


import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.Base64;

public class CryptoUtil {
    public static final byte[] SHARED_SECRET = "sharedsecret1234".getBytes(StandardCharsets.UTF_8);

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static byte[] hmac(byte[] key, byte[] data) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        return mac.doFinal(data);
    }

    public static SecretKey deriveKey(byte[] masterSecret, String label) throws Exception {
        byte[] derived = hmac(masterSecret, label.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(Arrays.copyOf(derived, 16), "AES");
    }

    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String encData, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encData);
        byte[] iv = Arrays.copyOfRange(decoded, 0, 12);
        byte[] cipherText = Arrays.copyOfRange(decoded, 12, decoded.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return new String(cipher.doFinal(cipherText));
    }

    public static String generateMAC(String data, SecretKey key) throws Exception {
        byte[] mac = hmac(key.getEncoded(), data.getBytes());
        return Base64.getEncoder().encodeToString(mac);
    }

    public static boolean verifyMAC(String data, String macEncoded, SecretKey key) throws Exception {
        byte[] mac = hmac(key.getEncoded(), data.getBytes());
        return MessageDigest.isEqual(Base64.getDecoder().decode(macEncoded), mac);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}

