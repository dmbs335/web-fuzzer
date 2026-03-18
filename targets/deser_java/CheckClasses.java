public class CheckClasses {
    public static void main(String[] args) {
        String[] classes = {
            "weblogic.deployment.jms.ForeignOpaqueReference",
            "weblogic.jms.common.StreamMessageForContainerImpl",
            "weblogic.jndi.internal.ForeignOpaqueReference",
            "weblogic.corba.utils.StubSerialWrapper",
            "weblogic.iiop.RemoteInvocation",
            "weblogic.jndi.internal.WLEventContextImpl",
            "weblogic.ejb.container.EjbRemoteRef",
            "weblogic.cluster.singleton.ClusterMasterRemote",
            "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy",
            "com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager",
            "com.bea.core.repackaged.springframework.beans.factory.config.ObjectFactoryCreatingFactoryBean$ObjectFactoryDelegatingInvocationHandler",
            "weblogic.wsee.jaxws.buffer.BufferingConfig$Queue",
            "weblogic.jdbc.rowset.SQLComparator",
            "weblogic.corba.utils.MarshalledObject",
            "weblogic.iiop.ProxyDesc",
            "weblogic.management.internal.WebLogicAttribute$NullObject",
        };
        for (String cn : classes) {
            try {
                Class<?> c = Class.forName(cn, false, Thread.currentThread().getContextClassLoader());
                boolean ser = java.io.Serializable.class.isAssignableFrom(c);
                // Check readObject/readResolve
                boolean hasRO = false, hasRR = false;
                for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                    if (m.getName().equals("readObject")) hasRO = true;
                    if (m.getName().equals("readResolve")) hasRR = true;
                }
                // Check key interfaces
                java.util.Set<String> ifaces = new java.util.HashSet<>();
                Class<?> walk = c;
                while (walk != null && walk != Object.class) {
                    for (Class<?> i : walk.getInterfaces()) ifaces.add(i.getName());
                    walk = walk.getSuperclass();
                }
                System.out.println((ser ? "[SER]" : "[---]") + " " + cn +
                    " readObj=" + hasRO + " readRes=" + hasRR +
                    " ifaces=" + ifaces);
            } catch (Throwable t) {
                System.out.println("[ERR] " + cn + " : " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
    }
}
