package com.danielhedren.encryption;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for generating keys, encrypting and decrypting
 */
public class AESEncrypt {
    private static final String CIPHER_STRING = "AES/CBC/PKCS5Padding";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int ITERATION_COUNT = 1000;
    private static final Charset CHARSET = StandardCharsets.UTF_8;

    /**
     * Generates a key from the supplied arguments or a random salt if none is supplied
     * Adapted from https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html
     *
     * @param secret The secret to use for generating the key
     * @param salt   32 bytes of data, or null
     * @return The key
     */
    public static SecretKey generateKey(final String secret, byte[] salt) {
        int saltLength = 32; // bytes; should be the same size as the output (256 / 8 = 32)
        int keyLength = 256; // 256-bits for AES-256, 128-bits for AES-128, etc

        /* When first creating the key, obtain a salt with this: */
        if (salt == null) {
            SecureRandom random = new SecureRandom();
            salt = new byte[saltLength];
            random.nextBytes(salt);
        }

        /* Use this to derive the key from the password: */
        KeySpec keySpec = new PBEKeySpec(secret.toCharArray(), salt, ITERATION_COUNT, keyLength);
        SecretKeyFactory keyFactory;

        try {
            keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }

        byte[] keyBytes;

        try {
            keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        return key;
    }

    /**
     * Utility method to encrypt strings
     */
    public static byte[] encrypt(final String message, final SecretKey secretKey) throws Exception {
       return encrypt(message.getBytes(CHARSET), secretKey);
    }

    /**
     * Encrypts a byte array with the given key
     */
    public static byte[] encrypt(final byte[] messageBytes, final SecretKey secretKey) throws Exception {
        byte[] initializationVector = new byte[16];
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // Create a new secure IV for every message
        (new SecureRandom()).nextBytes(initializationVector);

        Cipher cipher = Cipher.getInstance(CIPHER_STRING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(initializationVector));
        byte[] encryptedString = cipher.doFinal(messageBytes);

        // Prepend the IV to the encrypted message. The IV is not secret
        outputStream.write(initializationVector);
        outputStream.write(encryptedString);

        return outputStream.toByteArray();
    }

    /**
     * Utility method for decrypting to a string
     */
    public static String decryptToString(final byte[] messageBytes, final SecretKey secretKey) throws Exception {
        return new String(decrypt(messageBytes, secretKey), CHARSET);
    }

    /**
     * Decrypts a byte array with the given key
     *
     * @return The decrypted bytes, or null if decryption was not possible
     */
    public static byte[] decrypt(final byte[] messageBytes, final SecretKey secretKey) throws Exception {
        if (messageBytes.length <= 16) {
            return null;
        }

        // Get our initialization vector
        byte[] initializationVector = Arrays.copyOfRange(messageBytes, 0, 16);

        // And our message
        byte[] message = Arrays.copyOfRange(messageBytes, 16, messageBytes.length);

        Cipher cipher = Cipher.getInstance(CIPHER_STRING);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initializationVector));

        byte[] decryptedBytes;
        try {
            decryptedBytes = cipher.doFinal(message);
        } catch (Exception e) {
            return null;
        }

        return decryptedBytes;
    }
}
