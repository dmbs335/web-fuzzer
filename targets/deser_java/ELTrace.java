
public class ELTrace {
    public static void main(String[] args) throws Exception {
        Class<?> elp = Class.forName("javax.el.ELProcessor");
        System.out.println("ELProcessor class: " + elp.getName());
        System.out.println("ELProcessor source: " + elp.getProtectionDomain().getCodeSource().getLocation());

        // Try to create instance
        Object inst = elp.getDeclaredConstructor().newInstance();
        System.out.println("Instance: " + inst.getClass().getName());

        // Try eval
        java.lang.reflect.Method evalMethod = elp.getMethod("eval", String.class);
        System.out.println("eval method: " + evalMethod);

        try {
            Object result = evalMethod.invoke(inst, "1+1");
            System.out.println("eval('1+1') = " + result);
        } catch (Exception e) {
            System.out.println("eval failed: " + e.getCause());
        }

        try {
            Object result = evalMethod.invoke(inst, "Runtime.getRuntime()");
            System.out.println("eval('Runtime.getRuntime()') = " + result);
        } catch (Exception e) {
            System.out.println("eval('Runtime.getRuntime()') failed: " + e.getCause().getClass().getName() + ": " + e.getCause().getMessage());
        }
    }
}
