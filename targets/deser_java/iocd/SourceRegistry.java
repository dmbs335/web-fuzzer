package iocd;

import iocd.GadgetGraph.SourceDescriptor;
import iocd.ClassDatabase.ClassInfo;
import iocd.ClassDatabase.MethodInfo;
import iocd.ClassDatabase.CallSite;
import org.objectweb.asm.Opcodes;

import java.util.*;

/**
 * Identifies deserialization entry points (sources).
 *
 * Sources are classes whose readObject/readResolve/readExternal methods
 * dispatch a virtual call on an attacker-controlled field, enabling
 * the first step of a gadget chain.
 *
 * JDK sources (HashMap, PriorityQueue, etc.) are hardcoded since their
 * bytecode isn't in the scanned JARs. Library sources are discovered
 * automatically by analyzing readObject methods.
 */
public class SourceRegistry {

    // ── Hardcoded JDK sources ────────────────────────────────────

    private static final List<SourceDescriptor> JDK_SOURCES = List.of(
        // hashCode-based: readObject → putVal/reconstitutionPut → key.hashCode()
        new SourceDescriptor("java.util.HashMap", "readObject", "hashCode", null),
        new SourceDescriptor("java.util.HashSet", "readObject", "hashCode", null),
        new SourceDescriptor("java.util.LinkedHashSet", "readObject", "hashCode", null),
        new SourceDescriptor("java.util.Hashtable", "readObject", "hashCode", null),
        new SourceDescriptor("java.util.concurrent.ConcurrentHashMap", "readObject", "hashCode", null),

        // compare-based: readObject → heapify/put → comparator.compare()
        new SourceDescriptor("java.util.PriorityQueue", "readObject", "compare", "java.util.Comparator"),
        new SourceDescriptor("java.util.TreeMap", "readObject", "compare", "java.util.Comparator"),
        new SourceDescriptor("java.util.TreeSet", "readObject", "compare", "java.util.Comparator"),

        // toString-based: readObject → val.toString()
        new SourceDescriptor("javax.management.BadAttributeValueExpException", "readObject", "toString", null)
    );

    // Dispatchable methods that sources call on attacker-controlled objects
    private static final Set<String> DISPATCH_METHODS = Set.of(
        "hashCode", "equals", "compareTo", "compare", "toString",
        "get", "invoke", "run", "call", "iterator", "getValue", "getKey",
        "transform", "execute", "apply", "accept"
    );

    // ── Source discovery ─────────────────────────────────────────

    public List<SourceDescriptor> findSources(ClassDatabase db) {
        List<SourceDescriptor> sources = new ArrayList<>(JDK_SOURCES);

        // Scan library classes for custom readObject/readResolve/readExternal
        for (ClassInfo ci : db.allClasses()) {
            if (!ci.serializable) continue;
            if (ci.isInterface() || ci.isAbstract()) continue;

            // Check readObject
            MethodInfo readObj = ci.getMethod("readObject");
            if (readObj != null) {
                analyzeEntryMethod(ci, readObj, "readObject", sources, db);
            }

            // Check readResolve
            MethodInfo readResolve = ci.getMethod("readResolve");
            if (readResolve != null) {
                analyzeEntryMethod(ci, readResolve, "readResolve", sources, db);
            }

            // Check readExternal (Externalizable)
            MethodInfo readExt = ci.getMethod("readExternal");
            if (readExt != null) {
                analyzeEntryMethod(ci, readExt, "readExternal", sources, db);
            }
        }

        return sources;
    }

    private void analyzeEntryMethod(ClassInfo ci, MethodInfo mi, String entryName,
                                     List<SourceDescriptor> sources, ClassDatabase db) {
        // Skip JDK sources (already hardcoded)
        for (SourceDescriptor jdk : JDK_SOURCES) {
            if (jdk.className.equals(ci.name)) return;
        }

        // Look for virtual/interface dispatch calls in this method
        for (CallSite cs : mi.callSites) {
            if (cs.opcode != Opcodes.INVOKEVIRTUAL && cs.opcode != Opcodes.INVOKEINTERFACE) continue;

            // Is this calling a dispatch method?
            if (!DISPATCH_METHODS.contains(cs.name)) continue;

            // Determine the dispatch interface
            String dispatchIface = cs.owner.replace('/', '.');

            // Only add if the dispatch target is an interface or abstract class with >1 impl
            Set<String> impls = db.getSerializableImplementors(dispatchIface);
            if (impls.size() >= 1) {
                sources.add(new SourceDescriptor(
                    ci.name, entryName, cs.name, dispatchIface
                ));
                break; // One source per class per entry method
            }

            // For hashCode/toString/equals, dispatch goes to any object
            if (cs.name.equals("hashCode") || cs.name.equals("toString") || cs.name.equals("equals")) {
                sources.add(new SourceDescriptor(ci.name, entryName, cs.name, null));
                break;
            }
        }
    }
}
