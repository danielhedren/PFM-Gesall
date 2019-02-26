package com.danielhedren.gesall;

import android.util.Base64;

import com.danielhedren.encryption.RSAEncrypt;

import java.security.PrivateKey;
import java.security.PublicKey;

public class User {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String identifier;

    public User(PublicKey publicKey) {
        this.publicKey = publicKey;

        identifier = Base64.encodeToString(RSAEncrypt.getSHA256Digest(publicKey.getEncoded()), Base64.NO_WRAP).substring(0, 8);
    }

    public User(PublicKey publicKey, PrivateKey privateKey) {
        this(publicKey);
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public SecureMessage.Message decryptMessage(SecureMessage message) {
        return null;
    }

    public String getName() {
        return identifier;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof User) {
            return this.publicKey.equals(((User) obj).publicKey);
        }

        return false;
    }

    @Override
    public int hashCode() {
        return publicKey.hashCode();
    }
}
