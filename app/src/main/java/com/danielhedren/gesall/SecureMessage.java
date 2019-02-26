package com.danielhedren.gesall;

import android.util.Base64;

import com.danielhedren.encryption.AESEncrypt;
import com.danielhedren.encryption.RSAEncrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * This class provides the data and methods required to secure a Message and prepare it
 * for transmission, as well as recovering and verifying SecureMessages along with their
 * wrapped Messages
 */
public class SecureMessage implements Serializable {
    public static final Charset CHARSET = StandardCharsets.UTF_8;

    public enum MessageType { TEXT, PUBKEY_REQUEST, PUBKEY_RESPONSE, DISCONNECT }

    // Variables required for decryption and verification, sent unencrypted
    private byte[] salt;
    private byte[] hash;

    // This is where the encrypted Message is stored
    private byte[] data;

    public SecureMessage() {
        data = null;

        salt = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
    }

    /**
     * Sign the message with a private key for later verification
     * @param privateKey
     * @return True if successful
     */
    public boolean sign(PrivateKey privateKey) {
        if (data == null || data.length == 0) {
            return false;
        }

        hash = RSAEncrypt.getSHA256Digest(data);

        try {
            hash = RSAEncrypt.encrypt(hash, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * Verify that the message was signed by the private key corresponding to publicKey
     * @param publicKey
     * @return True if verification was successful
     */
    public boolean verify(PublicKey publicKey) {
        if (hash == null || hash.length == 0) {
            return false;
        }

        byte[] decryptedHash;
        try {
            decryptedHash = RSAEncrypt.decrypt(hash, publicKey);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        if (Arrays.equals(decryptedHash, RSAEncrypt.getSHA256Digest(data))) {
            return true;
        }

        return false;
    }

    /**
     * Encrypt a Message and store it in this SecureMessages
     */
    public void encryptMessage(Message message, String secret) {
        SecretKey key = AESEncrypt.generateKey(secret, salt);
        encryptMessage(message, key);
    }

    /**
     * Encrypt a Message and store it in this SecureMessage
     */
    public void encryptMessage(Message message, SecretKey secretKey) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutput objectOutput;
        byte[] byteOutput;

        // Attempt serialization of message
        try {
            objectOutput = new ObjectOutputStream(byteArrayOutputStream);
            objectOutput.writeObject(message);
            objectOutput.flush();
            byteOutput = byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        byte[] encryptedOutput;

        // Attempt encryption of serialized data
        try {
            encryptedOutput = AESEncrypt.encrypt(byteOutput, secretKey);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        this.data = encryptedOutput;
    }

    /**
     * Decrypt the Message stored in this SecureMessage
     */
    public Message decryptMessage(String secret) {
        // Generate the key
        SecretKey key = AESEncrypt.generateKey(secret, salt);
        byte[] decryptedData;

        // Attempt decryption
        try {
            decryptedData = AESEncrypt.decrypt(data, key);
        } catch (Exception e) {
            return null;
        }

        // If the data could not be decrypted it is highly probable that it was not
        // meant for us
        if (decryptedData == null || decryptedData.length == 0) {
            return null;
        }

        // Get a byte array input stream for use with the object input stream
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decryptedData);
        ObjectInput objectInput;
        Object object;

        // Attempt to get an object from the message data
        try {
            objectInput = new ObjectInputStream(byteArrayInputStream);
            object = objectInput.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }

        // Make sure the object is a Message
        if (!(object instanceof Message)) {
            return null;
        }

        // We've got our message now
        Message message = (Message) object;

        return message;
    }

    /**
     * Encode this SecureMessage to a Base64 string
     */
    public String encodeToString() {
        return Base64.encodeToString(encode(), Base64.NO_WRAP);
    }

    /**
     * Encode this SecureMessage to a byte array
     */
    public byte[] encode() {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutput objectOutput;
        byte[] byteOutput;

        try {
            objectOutput = new ObjectOutputStream(byteArrayOutputStream);
            objectOutput.writeObject(this);
            objectOutput.flush();
            byteOutput = byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return byteOutput;
    }

    /**
     * Get a SecureMessage stored as a Base64 string
     */
    public static SecureMessage decodeFromString(String message) {
        byte[] decodedMessage;

        try {
            decodedMessage = Base64.decode(message, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            return null;
        }

        return decode(decodedMessage);
    }

    /**
     * Get a SecureMessage stored as a byte array
     */
    public static SecureMessage decode(byte[] messageData) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(messageData);
        ObjectInput objectInput;
        Object object;

        // Attempt to get an object from the message data
        try {
            objectInput = new ObjectInputStream(byteArrayInputStream);
            object = objectInput.readObject();
        } catch (IOException | ClassNotFoundException e) {
            return null;
        }

        // Make sure the object is a SecureMessage
        if (!(object instanceof SecureMessage)) {
            return null;
        }

        // We've got our message now
        SecureMessage secureMessage = (SecureMessage) object;

        return secureMessage;
    }

    /**
     * This class will securely store data once wrapped in a SecureMessage
     */
    public static class Message implements Serializable {
        public byte[] data;
        public MessageType messageType;

        public Message(byte[] data, MessageType messageType) {
            this.data = data;
            this.messageType = messageType;
        }

        public Message(String data, MessageType messageType) {
            this.data = data.getBytes(CHARSET);
            this.messageType = messageType;
        }

        public Message(String data) {
            this.data = data.getBytes(CHARSET);
            this.messageType = MessageType.TEXT;
        }

        public String getText() {
            return new String(data, CHARSET);
        }
    }
}
