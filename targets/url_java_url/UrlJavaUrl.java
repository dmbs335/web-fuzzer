import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * URL parser target - Java java.net.URL.
 *
 * Parses URLs using Java's java.net.URL and outputs parsed
 * components as JSON for differential comparison.
 *
 * java.net.URL differs from java.net.URI significantly:
 *   - URL resolves hostnames (triggers DNS!) — we suppress this
 *   - URL requires a known protocol handler
 *   - URL.equals() does DNS comparison (security risk!)
 *   - Different parsing of authority component
 *   - More lenient than URI for some edge cases
 *   - Relevant to SSRF in Java applications
 *
 * Modes:
 *   One-shot:   java UrlJavaUrl <file>
 *   Persistent:  java UrlJavaUrl --persistent
 *
 * References:
 *   - Java docs: java.net.URL (deprecated since Java 20)
 *   - SSRF in Java applications
 *   - Spring MVC URL handling
 */
@SuppressWarnings("deprecation")
public class UrlJavaUrl {

    static String parseUrl(String data) throws Exception {
        data = data.trim();
        if (data.isEmpty()) {
            throw new IllegalArgumentException("Empty input");
        }

        URL parsed = new URL(data);

        // Extract userinfo
        String userinfo = parsed.getUserInfo() != null ? parsed.getUserInfo() : "";

        // Extract host
        String host = parsed.getHost() != null ? parsed.getHost() : "";

        // Extract port
        String port = parsed.getPort() >= 0 ? String.valueOf(parsed.getPort()) : "";

        // Extract path
        String path = parsed.getPath() != null ? parsed.getPath() : "";

        // Extract query
        String query = parsed.getQuery() != null ? parsed.getQuery() : "";

        // Extract fragment (ref)
        String fragment = parsed.getRef() != null ? parsed.getRef() : "";

        // Extract scheme (protocol)
        String scheme = parsed.getProtocol() != null ? parsed.getProtocol() : "";

        // Build JSON manually
        return "{" +
            "\"fragment\":" + jsonString(fragment) + "," +
            "\"host\":" + jsonString(host) + "," +
            "\"path\":" + jsonString(path) + "," +
            "\"port\":" + jsonString(port) + "," +
            "\"query\":" + jsonString(query) + "," +
            "\"scheme\":" + jsonString(scheme) + "," +
            "\"userinfo\":" + jsonString(userinfo) +
            "}";
    }

    static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    // --- Persistent mode: binary protocol ---
    static void persistentMode() throws IOException {
        DataInputStream din = new DataInputStream(
            new BufferedInputStream(System.in));
        DataOutputStream dout = new DataOutputStream(
            new BufferedOutputStream(System.out));

        while (true) {
            int length;
            try {
                length = din.readInt();
            } catch (EOFException e) {
                break;
            }

            byte[] inputBytes = new byte[length];
            din.readFully(inputBytes);
            String input = new String(inputBytes, StandardCharsets.UTF_8);

            String output;
            int exitCode;
            try {
                output = parseUrl(input);
                exitCode = 0;
            } catch (Exception e) {
                output = "";
                exitCode = 1;
            }

            byte[] outBytes = output.getBytes(StandardCharsets.UTF_8);
            dout.writeInt(outBytes.length);
            dout.write(outBytes);
            dout.writeInt(exitCode);
            dout.flush();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--persistent")) {
            persistentMode();
            return;
        }

        if (args.length < 1) {
            System.err.println("Usage: java UrlJavaUrl <file>");
            System.err.println("       java UrlJavaUrl --persistent");
            System.exit(2);
        }

        String data;
        try {
            data = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
            System.exit(2);
            return;
        }

        try {
            String result = parseUrl(data);
            System.out.println(result);
            System.exit(0);
        } catch (Exception e) {
            System.err.println("REJECT: " + e.getMessage());
            System.exit(1);
        }
    }
}
