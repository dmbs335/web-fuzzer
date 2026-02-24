import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * URL parser target - Java java.net.URI.
 *
 * Parses URLs using Java's java.net.URI and outputs parsed
 * components as JSON for differential comparison.
 *
 * java.net.URI follows RFC 2396/3986 strictly:
 *   - Rejects many inputs that lenient parsers accept
 *   - Opaque vs hierarchical URI distinction
 *   - Different authority parsing from java.net.URL
 *   - Relevant to Log4Shell (CVE-2021-44228), Spring vulnerabilities
 *   - JNDI/LDAP injection chains use URI parsing
 *
 * Modes:
 *   One-shot:   java UrlJavaUri <file>
 *   Persistent:  java UrlJavaUri --persistent  (binary protocol on stdin/stdout)
 *
 * References:
 *   - Java docs: java.net.URI
 *   - RFC 2396 / RFC 3986
 *   - Log4Shell analysis
 */
public class UrlJavaUri {

    static String parseUrl(String data) throws Exception {
        data = data.trim();
        if (data.isEmpty()) {
            throw new IllegalArgumentException("Empty input");
        }

        URI parsed = new URI(data);

        // Extract userinfo
        String userinfo = parsed.getUserInfo() != null ? parsed.getUserInfo() : "";

        // Extract host
        String host = parsed.getHost() != null ? parsed.getHost() : "";

        // Extract port
        String port = parsed.getPort() >= 0 ? String.valueOf(parsed.getPort()) : "";

        // Extract path
        String path = parsed.getPath() != null ? parsed.getPath() : "";
        // For opaque URIs, use scheme-specific part
        if (path.isEmpty() && parsed.getSchemeSpecificPart() != null && !parsed.isOpaque()) {
            // hierarchical URI without path
        } else if (path.isEmpty() && parsed.isOpaque()) {
            path = parsed.getSchemeSpecificPart();
        }

        // Extract query
        String query = parsed.getQuery() != null ? parsed.getQuery() : "";

        // Extract fragment
        String fragment = parsed.getFragment() != null ? parsed.getFragment() : "";

        // Extract scheme
        String scheme = parsed.getScheme() != null ? parsed.getScheme() : "";

        // Build JSON manually (no external deps)
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
    // Request:  [4-byte BE length][UTF-8 data]
    // Response: [4-byte BE length][UTF-8 output][4-byte BE exit_code]

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
                break;  // Parent closed pipe
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
            System.err.println("Usage: java UrlJavaUri <file>");
            System.err.println("       java UrlJavaUri --persistent");
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
