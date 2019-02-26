package com.danielhedren.gesall;

import com.danielhedren.encryption.RSAEncrypt;

import java.security.PublicKey;
import java.util.function.Predicate;

public class ProtocolMessageHandler implements Server.MessageHandler {
    private final Server server;

    public ProtocolMessageHandler(Server server) {
        this.server = server;
    }

    @Override
    public void onChannelMessage(Channel channel, SecureMessage.Message message) {
        // Pubkey request, respond with ours
        if (message.messageType == SecureMessage.MessageType.PUBKEY_REQUEST) {
            server.send(new SecureMessage.Message(RSAEncrypt.keyToString(server.getLocalUser().getPublicKey()), SecureMessage.MessageType.PUBKEY_RESPONSE), channel);
        }

        // Add new user to channel
        if (message.messageType == SecureMessage.MessageType.PUBKEY_REQUEST || message.messageType == SecureMessage.MessageType.PUBKEY_RESPONSE) {
            PublicKey publicKey = RSAEncrypt.stringToPublicKey(message.getText());

            if (publicKey != null) {
                User user = new User(publicKey);
                if (!channel.getUsers().contains((user))) {
                    channel.getUsers().add(user);
                }
            }
        }

        // Remove disconnecting users from all channels
        if (message.messageType == SecureMessage.MessageType.DISCONNECT) {
            final PublicKey publicKey = RSAEncrypt.stringToPublicKey(message.getText());
            if (publicKey != null) {
                for (Channel c : server.getChannels()) {
                    c.getUsers().removeIf(new Predicate<User>() {
                        @Override
                        public boolean test(User u) {
                            return u.getPublicKey().equals(publicKey);
                        }
                    });
                }
            }
        }
    }

    @Override
    public void onUserMessage(User user, SecureMessage.Message message) {

    }
}
