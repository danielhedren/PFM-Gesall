package com.danielhedren.gesall;

import android.os.AsyncTask;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Handles connecting to the server
 */
class AsyncConnectionTask extends AsyncTask<Void, Void, Void> {
    private ResultHandler resultHandler;
    private ErrorHandler errorHandler;

    private String host;
    private int port;

    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    /**
     * @param resultHandler Run on successful connection
     */
    public AsyncConnectionTask(String host, int port, ResultHandler resultHandler) {
        this.host = host;
        this.port = port;
        this.resultHandler = resultHandler;
    }

    /**
     * Attempts to open a connection as well as input and output readers
     */
    @Override
    protected Void doInBackground(Void... args) {
        // Connect to the host
        try {
            socket = new Socket(host, port);
        } catch (IOException e) {
            if (errorHandler != null) errorHandler.onError(e);
            e.printStackTrace();
            return null;
        }

        // Open the input stream
        try {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
        } catch (IOException e) {
            if (errorHandler != null) errorHandler.onError(e);
            e.printStackTrace();
            return null;
        }

        // Open the output stream
        try {
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.ISO_8859_1), true);
        } catch (IOException e) {
            if (errorHandler != null) errorHandler.onError(e);
            e.printStackTrace();
            return null;
        }

        // Pass our results back
        resultHandler.onComplete(socket, in, out);

        return null;
    }

    /**
     * Set a handler for errors that occur during connection
     */
    public void setErrorHandler(ErrorHandler errorHandler) {
        this.errorHandler = errorHandler;
    }

    /**
     * Used to pass results back to the calling activity
     */
    public interface ResultHandler {
        void onComplete(Socket socket, BufferedReader in, PrintWriter out);
    }

    /**
     * Used to pass exceptions back to the calling activity
     */
    public interface ErrorHandler {
        void onError(Exception e);
    }
}
