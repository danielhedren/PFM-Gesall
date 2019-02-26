package com.danielhedren.gesall;

import android.os.AsyncTask;

import java.io.BufferedReader;
import java.io.IOException;

/**
 * Reads and decrypts SecureMessages
 */
class AsyncSecureReaderTask extends AsyncTask<Void, SecureMessage, Void> {
    private BufferedReader reader;
    private ResultHandler handler;

    /**
     * @param reader The reader object from an AsyncConnectionTask
     * @param handler A handler that receives SecureMessages
     */
    public AsyncSecureReaderTask(BufferedReader reader, ResultHandler handler) {
        this.reader = reader;
        this.handler = handler;
    }

    /**
     * Continuously reads any incoming data and forwards only SecureMessages to the handler
     */
    @Override
    protected Void doInBackground(Void... args) {
        String line;
        try {
            // Keep spinning until the task is cancelled
            while (!isCancelled()) {
                // We don't want to block on readLine so check if ready
                if (!reader.ready()) {
                    continue;
                }

                line = reader.readLine();

                // Break on EOF
                if (line == null) {
                    break;
                }

                // Decode our secure message
                SecureMessage secureMessage = SecureMessage.decodeFromString(line);

                // If it couldn't be decoded we don't care about it
                if (secureMessage == null) {
                    continue;
                }

                publishProgress(secureMessage);
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Passes on the SecureMessage - but this time on the UI thread
     */
    @Override
    protected void onProgressUpdate(SecureMessage... values) {
        handler.onMessage(values[0]);
    }

    /**
     * Interface for getting messages
     */
    public interface ResultHandler {
        void onMessage(SecureMessage secureMessage);
    }
}
