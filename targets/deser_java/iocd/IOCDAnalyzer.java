package iocd;

import iocd.ChainEnumerator.GadgetChain;
import iocd.GadgetGraph.SourceDescriptor;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * IOCD (Injection Object Construction Diagram) static analyzer for
 * Java deserialization gadget chain discovery.
 *
 * Scans JAR files using ASM to build a class database, identifies
 * deserialization sources and dangerous sinks, discovers intermediate
 * gadget links, enumerates valid chains, and outputs IR JSON seeds.
 *
 * Usage:
 *   java -cp "iocd_classes;gson.jar;asm.jar;asm-commons.jar" \
 *        iocd.IOCDAnalyzer \
 *        --jars "lib1.jar;lib2.jar;..." \
 *        --output path/to/output/ \
 *        [--max-depth 10] [--max-chains 1000] [--verbose]
 */
public class IOCDAnalyzer {

    public static void main(String[] args) throws Exception {
        // ── Parse arguments ──────────────────────────────────────
        String jarList = null;
        String outputDir = null;
        int maxDepth = 10;
        int maxChains = 200;
        boolean verbose = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--jars": jarList = args[++i]; break;
                case "--output": outputDir = args[++i]; break;
                case "--max-depth": maxDepth = Integer.parseInt(args[++i]); break;
                case "--max-chains": maxChains = Integer.parseInt(args[++i]); break;
                case "--verbose": verbose = true; break;
                default:
                    System.err.println("Unknown argument: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        if (jarList == null || outputDir == null) {
            printUsage();
            System.exit(1);
        }

        long startTime = System.currentTimeMillis();

        // ── Phase 1: Scan JARs ───────────────────────────────────
        log("Phase 1: Scanning JARs...");
        ClassDatabase db = new ClassDatabase();

        String[] jars = jarList.split("[;,:]");
        for (String jar : jars) {
            jar = jar.trim();
            if (jar.isEmpty()) continue;
            Path jarPath = Paths.get(jar);
            if (!Files.exists(jarPath)) {
                log("  WARN: JAR not found: " + jar);
                continue;
            }
            try {
                db.scanJar(jarPath);
                if (verbose) log("  Scanned: " + jar);
            } catch (Exception e) {
                log("  WARN: Failed to scan " + jar + ": " + e.getMessage());
            }
        }

        log("  Classes found: " + db.size());

        // ── Phase 2: Resolve hierarchy ───────────────────────────
        log("Phase 2: Resolving class hierarchy (CHA)...");
        db.resolveHierarchy();
        log("  Serializable classes: " + db.serializableCount());

        // ── Phase 3: Find sources ────────────────────────────────
        log("Phase 3: Finding deserialization sources...");
        SourceRegistry sourceReg = new SourceRegistry();
        List<SourceDescriptor> sources = sourceReg.findSources(db);
        log("  Sources found: " + sources.size());
        if (verbose) {
            for (SourceDescriptor s : sources) {
                log("    " + s.className + "." + s.entryMethod + " → " + s.dispatchMethod
                    + (s.dispatchInterface != null ? " [" + s.dispatchInterface + "]" : ""));
            }
        }

        // ── Phase 4: Find sinks ──────────────────────────────────
        log("Phase 4: Finding dangerous sinks...");
        SinkRegistry sinkReg = new SinkRegistry();
        sinkReg.findSinks(db);
        log("  Sink classes found: " + sinkReg.size());
        if (verbose) {
            for (var entry : sinkReg.allClassSinks().entrySet()) {
                log("    " + entry.getKey() + " → " + entry.getValue().sinkCategory
                    + " via " + entry.getValue().viaMethod);
            }
        }

        // ── Phase 5: Analyze links ───────────────────────────────
        log("Phase 5: Analyzing gadget links...");
        GadgetGraph graph = new GadgetGraph();

        // Add sources to graph
        for (SourceDescriptor src : sources) {
            graph.addSource(src);
        }

        // Analyze links and build edges
        LinkAnalyzer linkAnalyzer = new LinkAnalyzer();
        linkAnalyzer.analyze(db, sinkReg, graph);
        log("  Graph nodes: " + graph.nodeCount()
            + " (links=" + graph.linkCount() + ", sinks=" + graph.sinkCount() + ")");
        log("  Graph edges: " + graph.edgeCount());

        // ── Phase 6: Enumerate chains ────────────────────────────
        log("Phase 6: Enumerating gadget chains (max_depth=" + maxDepth
            + ", max_chains=" + maxChains + ")...");
        ChainEnumerator enumerator = new ChainEnumerator(graph, db, maxDepth, maxChains);
        List<GadgetChain> chains = enumerator.enumerate();
        log("  Chains discovered: " + chains.size());

        if (verbose && !chains.isEmpty()) {
            // Print first 20 chains
            int show = Math.min(20, chains.size());
            for (int i = 0; i < show; i++) {
                GadgetChain c = chains.get(i);
                StringBuilder sb = new StringBuilder();
                sb.append("    [").append(i).append("] ");
                sb.append(c.source.className).append(" → ");
                for (ChainEnumerator.ChainLink cl : c.links) {
                    String simple = cl.node.className;
                    int dot = simple.lastIndexOf('.');
                    if (dot >= 0) simple = simple.substring(dot + 1);
                    sb.append(simple).append(" → ");
                }
                sb.append("[").append(c.sinkCategory).append("]");
                sb.append(" (depth=").append(c.depth()).append(")");
                log(sb.toString());
            }
            if (chains.size() > show) {
                log("    ... and " + (chains.size() - show) + " more");
            }
        }

        // ── Phase 7: Emit IR JSON ────────────────────────────────
        log("Phase 7: Emitting IR JSON seeds...");
        Path outPath = Paths.get(outputDir);
        IREmitter emitter = new IREmitter();
        int written = emitter.writeChains(chains, outPath);
        log("  Seeds written: " + written);

        // Write metadata
        emitter.writeTypeHierarchy(db.getTypeHierarchy(), outPath);
        emitter.writeFieldContracts(db, outPath);

        long elapsed = System.currentTimeMillis() - startTime;
        emitter.writeStats(db.size(), db.serializableCount(), sources.size(),
            sinkReg.size(), graph.linkCount(), graph.edgeCount(), chains.size(),
            elapsed, outPath);

        log("");
        log("═══════════════════════════════════════════════════");
        log("  IOCD Analysis Complete");
        log("  Classes scanned:    " + db.size());
        log("  Serializable:       " + db.serializableCount());
        log("  Sources:            " + sources.size());
        log("  Sinks:              " + sinkReg.size());
        log("  Graph nodes:        " + graph.nodeCount());
        log("  Graph edges:        " + graph.edgeCount());
        log("  Chains discovered:  " + chains.size());
        log("  Seeds written:      " + written);
        log("  Elapsed:            " + elapsed + "ms");
        log("  Output:             " + outPath.toAbsolutePath());
        log("═══════════════════════════════════════════════════");
    }

    private static void log(String msg) {
        System.err.println("[IOCD] " + msg);
    }

    private static void printUsage() {
        System.err.println("Usage: java iocd.IOCDAnalyzer --jars <jar1;jar2;...> --output <dir> [options]");
        System.err.println("Options:");
        System.err.println("  --max-depth N    Max chain depth (default: 10)");
        System.err.println("  --max-chains N   Max chains to enumerate (default: 500)");
        System.err.println("  --verbose        Print detailed analysis info");
    }
}
