package com.danielhedren.gesall;

import android.os.AsyncTask;

import java.io.PrintWriter;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.SecretKey;

/**
 * Writes SecureMessages
 */
class AsyncSecureWriterTask extends AsyncTask<SecureMessage.Message, Void, Void> {
    private PrintWriter out;
    private String secretString;
    private PrivateKey privateKey;
    private SecretKey secretKey;

    /**
     * @param out The PrintWriter from an AsyncConnectionTask
     * @param secretString A string to base the symmetric encryption on
     * @param privateKey The key with which to sign the data, can be null to disable signing
     */
    public AsyncSecureWriterTask(PrintWriter out, String secretString, PrivateKey privateKey) {
        this.out = out;
        this.secretString = secretString;
        this.privateKey = privateKey;
    }

    /**
     * @param out The PrintWriter from an AsyncConnectionTask
     * @param secretKey A key to use for the symmetric encryption
     * @param privateKey The key with which to sign the data, can be null to disable signing
     */
    public AsyncSecureWriterTask(PrintWriter out, SecretKey secretKey, PrivateKey privateKey) {
        this.out = out;
        this.secretKey = secretKey;
        this.privateKey = privateKey;
    }

    /**
     * Sends any number of SecureMessages
     */
    @Override
    protected Void doInBackground(SecureMessage.Message... messages) {
        for (SecureMessage.Message message : messages) {
            try {
                // Create a new SecureMessage
                SecureMessage secureMessage = new SecureMessage();

                // Set the payload
                if (secretKey != null) {
                    secureMessage.encryptMessage(message, secretKey);
                } else if (secretString != null) {
                    secureMessage.encryptMessage(message, secretString);
                } else {
                    throw new Exception("No basis for encryption given.");
                }

                if (privateKey != null) secureMessage.sign(privateKey);

                // Send the message
                out.println(secureMessage.encodeToString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return null;
    }
}
