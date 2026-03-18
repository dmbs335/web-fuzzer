/**
 * Base64 text-protocol wrapper for DeserTarget persistent mode.
 * Reads base64-encoded requests (one per line) from stdin,
 * forwards binary to DeserTarget persistent process,
 * reads response, base64-encodes and writes to stdout.
 *
 * Avoids Windows binary stdin piping issues with docker exec -i.
 *
 * Usage: java -cp <classpath> DeserB64Wrapper [DeserTarget args...]
 */
import java.io.*;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;

public class DeserB64Wrapper {
    public static void main(String[] args) throws Exception {
        // Build command for DeserTarget
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>();
        cmd.add("java");
        cmd.add("-cp");
        cmd.add(cp);
        cmd.add("DeserTarget");
        cmd.add("--persistent");
        for (String a : args) cmd.add(a);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process proc = pb.start();
        OutputStream toChild = proc.getOutputStream();
        InputStream fromChild = proc.getInputStream();
        DataOutputStream dos = new DataOutputStream(toChild);
        DataInputStream dis = new DataInputStream(fromChild);

        // Signal ready
        System.out.println("READY");
        System.out.flush();

        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();

        String line;
        while ((line = stdin.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Decode base64 request
            byte[] payload = decoder.decode(line);

            // Forward to DeserTarget: 4-byte BE length + payload
            dos.writeInt(payload.length);
            dos.write(payload);
            dos.flush();

            // Read response: 4-byte length + body + 4-byte exit code
            int respLen = dis.readInt();
            byte[] body = new byte[respLen];
            dis.readFully(body);
            int exitCode = dis.readInt();

            // Build full response: length(4) + body + exitCode(4)
            ByteArrayOutputStream bos = new ByteArrayOutputStream(respLen + 8);
            DataOutputStream resp = new DataOutputStream(bos);
            resp.writeInt(respLen);
            resp.write(body);
            resp.writeInt(exitCode);
            resp.flush();

            // Base64 encode and write
            System.out.println(encoder.encodeToString(bos.toByteArray()));
            System.out.flush();
        }

        proc.destroyForcibly();
    }
}
