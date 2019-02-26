package com.danielhedren.gesall;

import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.danielhedren.encryption.RSAEncrypt;

import java.security.KeyPair;

/**
 * App that expands on 8.1 and 8.2, allowing fairly secure channel based chatting as well as
 * secure user-to-user communication utilizing a per-message DH-exchange enabling forward
 * secrecy.
 *
 * Users should be able to attempt to establish direct communication via UDP.
 *
 * Users are identified by their public keys and the local user can alias other users, making it
 * easier to identify trusted peers
 *
 * App lifecycle
 * # Broadcast online message
 * # Request response from users on the contact list
 * # Start listening on users preferred channels
 *
 * UX requirements
 * # Join channel
 * # Send channel message
 * # Add contact
 * # Check contact list
 * # Send contact message (receive receipt, probably required anyway for forward secrecy)
 */
public class MainActivity extends AppCompatActivity {
    //public static final String HOST = "atlas.dsv.su.se";
    //public static final int PORT = 9494;

    public static final String HOST = "192.168.1.109";
    public static final int PORT = 2000;

    private KeyPair keyPair;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize preferences
        SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(this);

        // Initialize or fetch RSA keys as required
        if (!preferences.contains("publicKey")) {
            keyPair = RSAEncrypt.generateKeyPair();
            SharedPreferences.Editor editor = preferences.edit();
            editor.putString("publicKey", RSAEncrypt.keyToString(keyPair.getPublic()));
            editor.putString("privateKey", RSAEncrypt.keyToString(keyPair.getPrivate()));
            editor.apply();
        } else {
            keyPair = new KeyPair(RSAEncrypt.stringToPublicKey(preferences.getString("publicKey", null)),
                    RSAEncrypt.stringToPrivateKey(preferences.getString("privateKey", null)));
        }

        User localUser = new User(keyPair.getPublic(), keyPair.getPrivate());
        Server server = new Server(HOST, PORT);
        server.setLocalUser(localUser);
        server.connect();

        server.addMessageHandler(new Server.MessageHandler() {
            @Override
            public void onChannelMessage(Channel channel, SecureMessage.Message message) {
                if (channel.isBroadcast()) {
                    if (message.messageType == SecureMessage.MessageType.PUBKEY_REQUEST) {
                        Log.d("BROADCAST", "PUBKEY_REQUEST");
                    } else {
                        Log.d("BROADCAST", message.getText());
                    }
                } else {
                    Log.d("CHANNEL", "[" + channel + "] " + message.getText());
                }
            }

            @Override
            public void onUserMessage(User user, SecureMessage.Message message) {
                Log.d("USER", "[" + user + "] " + message.getText());
            }
        });
    }
}
