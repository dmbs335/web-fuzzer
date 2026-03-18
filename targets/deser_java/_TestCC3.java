import org.apache.commons.collections.comparators.TransformingComparator;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import java.io.Serializable;
public class _TestCC3 {
    public static void main(String[] args) {
        System.out.println("TransformingComparator: " + Serializable.class.isAssignableFrom(TransformingComparator.class));
        System.out.println("InvokerTransformer: " + Serializable.class.isAssignableFrom(InvokerTransformer.class));
        System.out.println("ConstantTransformer: " + Serializable.class.isAssignableFrom(ConstantTransformer.class));
        System.out.println("ChainedTransformer: " + Serializable.class.isAssignableFrom(ChainedTransformer.class));
    }
}
