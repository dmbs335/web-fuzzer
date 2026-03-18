import java.io.*;

public class DeserTest {
    public static void main(String[] args) throws Exception {
        System.out.println("Reading payload...");
        File f = new File("/tmp/wl9_payload.bin");
        byte[] data = new byte[(int) f.length()];
        try (FileInputStream fis = new FileInputStream(f)) {
            fis.read(data);
        }
        System.out.println("Payload size: " + data.length);

        System.out.println("Deserializing (with full WebLogic classpath)...");
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            System.out.println("Result: " + obj.getClass().getName());
            System.out.println("DESERIALIZATION SUCCEEDED");
        } catch (Throwable e) {
            System.out.println("Exception: " + e.getClass().getName());
            String msg = e.getMessage();
            if (msg != null) System.out.println("Message: " + (msg.length() > 300 ? msg.substring(0, 300) : msg));
            Throwable cause = e.getCause();
            int depth = 0;
            while (cause != null && depth < 10) {
                System.out.println("  Caused by [" + depth + "]: " + cause.getClass().getName() + ": " +
                    (cause.getMessage() != null ? (cause.getMessage().length() > 200 ? cause.getMessage().substring(0, 200) : cause.getMessage()) : "null"));
                cause = cause.getCause();
                depth++;
            }
        }
    }
}
