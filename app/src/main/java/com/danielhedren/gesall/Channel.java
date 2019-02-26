package com.danielhedren.gesall;

import java.util.ArrayList;

public class Channel {
    public final static String BROADCAST = "SERVER";
    public static Channel broadcast;
    private Server server;
    private String name;
    private ArrayList<User> users;

    public Channel(Server server, String name) {
        this.server = server;
        this.name = name;
        users = new ArrayList<>();

        if (isBroadcast()) broadcast = this;
    }

    public boolean isBroadcast() {
        return this.name.equals(BROADCAST);
    }

    public void connect() {

    }

    public String getName() {
        return name;
    }

    public SecureMessage.Message decryptMessage(SecureMessage message) {
        return message.decryptMessage(name);
    }

    @Override
    public String toString() {
        return getName();
    }

    public ArrayList<User> getUsers() {
        return users;
    }
}
