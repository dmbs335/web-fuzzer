/**
 * TCP wrapper for DeserTarget persistent mode.
 * Listens on a port and forwards 4-byte BE length-prefixed messages
 * to DeserTarget, returning responses over the same TCP connection.
 *
 * Usage: java -cp <classpath> DeserTcpServer <port> [DeserTarget args...]
 * Example: java -cp ... DeserTcpServer 9900 --classpath weblogic --filter weblogic
 */
import java.io.*;
import java.net.*;

public class DeserTcpServer {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: DeserTcpServer <port> [DeserTarget args...]");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);

        // Pass remaining args to DeserTarget (prepend --persistent)
        String[] dtArgs = new String[args.length]; // +0 since we replace port with --persistent
        dtArgs[0] = "--persistent";
        System.arraycopy(args, 1, dtArgs, 1, args.length - 1);

        // Start DeserTarget in a child process so we can pipe stdin/stdout
        String cp = System.getProperty("java.class.path");
        ProcessBuilder pb = new ProcessBuilder("java", "-cp", cp, "DeserTarget");
        for (String a : dtArgs) pb.command().add(a);
        pb.redirectErrorStream(false);

        ServerSocket ss = new ServerSocket(port);
        System.err.println("[DeserTcpServer] Listening on port " + port);

        while (true) {
            Socket client = ss.accept();
            System.err.println("[DeserTcpServer] Client connected from " + client.getRemoteSocketAddress());

            Process proc = pb.start();
            OutputStream toChild = proc.getOutputStream();
            InputStream fromChild = proc.getInputStream();
            InputStream clientIn = client.getInputStream();
            OutputStream clientOut = client.getOutputStream();

            // Forward thread: client -> child stdin
            Thread fwd = new Thread(() -> {
                try {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = clientIn.read(buf)) > 0) {
                        toChild.write(buf, 0, n);
                        toChild.flush();
                    }
                } catch (IOException e) {
                    // client disconnected
                } finally {
                    try { toChild.close(); } catch (IOException e) {}
                }
            });
            fwd.setDaemon(true);
            fwd.start();

            // Forward thread: child stdout -> client
            Thread rev = new Thread(() -> {
                try {
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = fromChild.read(buf)) > 0) {
                        clientOut.write(buf, 0, n);
                        clientOut.flush();
                    }
                } catch (IOException e) {
                    // child died or client disconnected
                }
            });
            rev.setDaemon(true);
            rev.start();

            try {
                rev.join(); // wait for child to finish
            } catch (InterruptedException e) {}

            proc.destroyForcibly();
            client.close();
            System.err.println("[DeserTcpServer] Client disconnected, waiting for next...");
        }
    }
}
