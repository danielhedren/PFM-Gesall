package com.danielhedren.gesall;

import android.os.AsyncTask;
import android.util.Log;

import com.danielhedren.encryption.DiffieHellman;
import com.danielhedren.encryption.RSAEncrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;

/**
 * Handles the connection to a server, joining channels and sending messages
 */
public class Server {
    public static final Charset CHARSET = StandardCharsets.UTF_8;

    private ArrayList<Channel> channels = new ArrayList<>();

    private ArrayList<MessageHandler> messageHandlers = new ArrayList<>();

    private String host;
    private int port;
    private AsyncSecureReaderTask readerTask;

    private User localUser;

    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    public Server(String host, int port) {
        this.host = host;
        this.port = port;

        joinChannel(Channel.BROADCAST);

        addMessageHandler(new ProtocolMessageHandler(this));
    }

    public User getLocalUser() {
        return localUser;
    }

    public void setLocalUser(User user) {
        localUser = user;
    }

    /**
     * Returns the connection status of the socket
     * @return true if the socket is connected
     */
    public boolean isConnected() {
        return socket.isConnected();
    }

    /**
     * Connect to the specified server
     */
    public void connect() {
        AsyncConnectionTask connectionTask = new AsyncConnectionTask(host, port, new AsyncConnectionTask.ResultHandler() {
            @Override
            public void onComplete(Socket s, BufferedReader i, PrintWriter o) {
                socket = s;
                in = i;
                out = o;

                // Create the task for reading and decrypting incoming messages
                readerTask = new AsyncSecureReaderTask(in, new AsyncSecureReaderTask.ResultHandler() {
                    @Override
                    public void onMessage(SecureMessage secureMessage) {
                        SecureMessage.Message message;
                        // We need to attempt to decrypt the message for every channel. This is
                        // sort of expensive but it's how the protocol works, otherwise we would
                        // have to send a plaintext identifier which would be bad.
                        for (Channel c : channels) {
                            message = c.decryptMessage(secureMessage);

                            if (message != null) {
                                for (MessageHandler h : messageHandlers) {
                                    h.onChannelMessage(c, message);
                                }
                                return; // We're done at this point
                            }
                        }

                        // If none of the channels could decrypt the message, it's probably a user
                        // message
                        for (User u : Channel.broadcast.getUsers()) {
                            message = u.decryptMessage(secureMessage);

                            if (message != null) {
                                for (MessageHandler h : messageHandlers) {
                                    h.onUserMessage(u, message);
                                }
                                return;
                            }
                        }
                    }
                });
                readerTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);

                // Send connection message
                broadcast(new SecureMessage.Message(RSAEncrypt.keyToString(localUser.getPublicKey()), SecureMessage.MessageType.PUBKEY_REQUEST));
            }
        });
        connectionTask.setErrorHandler(new AsyncConnectionTask.ErrorHandler() {
            @Override
            public void onError(Exception e) {
                Log.d("CONNECTION ERROR", e.getMessage());
            }
        });
        connectionTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

    /**
     * Closes the server connection
     */
    public void disconnect() {
        broadcast(new SecureMessage.Message(RSAEncrypt.keyToString(localUser.getPublicKey()), SecureMessage.MessageType.DISCONNECT));

        if (isConnected()) {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Join a channel
     * @param name the name of the channel
     */
    public void joinChannel(String name) {
        if (getChannelByName(name) != null) return;

        Channel channel = new Channel(this, name);
        channel.connect();

        channels.add(channel);
    }

    /**
     * Returns the channel with the given name if it is in the list of joined channels
     * @param name the name of the channel to find, case sensitive
     * @return the Channel if joined, else null
     */
    public Channel getChannelByName(String name) {
        for (Channel c : channels) {
            if (c.getName().equals(name)) {
                return c;
            }
        }

        return null;
    }

    public ArrayList<Channel> getChannels() {
        return channels;
    }

    /**
     * Add a handler to the list of handlers that are invoked on a successful message decryption
     * @param messageHandler the handler to add
     */
    public void addMessageHandler(MessageHandler messageHandler) {
        messageHandlers.add(messageHandler);
    }

    /**
     * Remove a handler from the list of active handlers
     * @param messageHandler the handler to remove
     */
    public void removeMessageHandler(MessageHandler messageHandler) {
        messageHandlers.remove(messageHandler);
    }

    public void sendToUser(String text, User recipient) {
        DiffieHellman dh = new DiffieHellman();

        SecureMessage.Message message = new SecureMessage.Message(text.getBytes(CHARSET), SecureMessage.MessageType.TEXT);
        SecureMessage secureMessage = new SecureMessage();
        secureMessage.encryptMessage(message, dh.generateSharedKey());
    }

    public void send(String text, Channel channel) {
        SecureMessage.Message message = new SecureMessage.Message(text.getBytes(CHARSET), SecureMessage.MessageType.TEXT);
        send(message, channel);
    }

    public void send(SecureMessage.Message message, Channel channel) {
        AsyncSecureWriterTask writerTask = new AsyncSecureWriterTask(out, channel.getName(), localUser.getPrivateKey());
        writerTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, message);
    }

    public void broadcast(String text) {
        SecureMessage.Message message = new SecureMessage.Message(text.getBytes(CHARSET), SecureMessage.MessageType.TEXT);
        broadcast(message);
    }

    public void broadcast(SecureMessage.Message message) {
        AsyncSecureWriterTask writerTask = new AsyncSecureWriterTask(out, Channel.BROADCAST, localUser.getPrivateKey());
        writerTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, message);
    }

    public interface MessageHandler {
        void onChannelMessage(Channel channel, SecureMessage.Message message);
        void onUserMessage(User user, SecureMessage.Message message);
    }
}
