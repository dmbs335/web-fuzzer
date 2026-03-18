
import org.apache.commons.collections4.functors.InvokerTransformer;
import java.io.Serializable;
public class _TestCC4 {
    public static void main(String[] args) {
        System.out.println(Serializable.class.isAssignableFrom(InvokerTransformer.class));
    }
}
