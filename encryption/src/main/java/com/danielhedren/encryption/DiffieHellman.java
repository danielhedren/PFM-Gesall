package com.danielhedren.encryption;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for handling Diffie-Hellman key exhanges
 *
 * Usage:
 * DiffieHellman bob = new DiffieHellman();
 * DiffieHellman alice = new DiffieHellman();
 *
 * alice.setPartnerPublicKey(bob.getPublicKey());
 * bob.setPartnerPublicKey(alice.getPublicKey());
 *
 * assert(bob.generateSharedKey() == alice.generateSharedKey()); // true
 */
public class DiffieHellman {
    private PublicKey publicKey;
    private KeyAgreement keyAgreement;
    private byte[] sharedSecret;

    public DiffieHellman() {
        makeKeyExchangeParams();
    }

    /**
     * Initialize the required parameters
     */
    private void makeKeyExchangeParams() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            publicKey = kp.getPublic();
            keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(kp.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Set the partners public key component retrieved over plaintext
     * @param publickey The partners public key
     */
    public void setPartnerPublicKey(PublicKey publickey) {
        try {
            keyAgreement.doPhase(publickey, true);
            sharedSecret = keyAgreement.generateSecret();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * @return Our public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Get the AES key derived from the shared data
     * @return The composite AES key
     */
    public SecretKey generateSharedKey() {
        return new SecretKeySpec(sharedSecret, "AES");
    }
}
