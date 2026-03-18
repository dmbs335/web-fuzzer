#!/bin/bash
# Build script for Java deserialization gadget fuzzing targets.
# Downloads gadget libraries + JSON parser, compiles DeserTarget.
set -e
cd "$(dirname "$0")"

MAVEN="https://repo1.maven.org/maven2"

# Library versions
CC3_VER="3.2.2"
CC4_VER="4.4"
CB_VER="1.9.4"
COMMONS_LOG_VER="1.3.4"
GSON_VER="2.11.0"
ASM_VER="9.7"

# Extended library versions (JDD gadget chains)
ROME_VER="1.0"
GROOVY_VER="2.4.21"
HIBERNATE_VER="5.6.15.Final"
BEANSHELL_VER="2.0b5"
SPRING_BEANS_VER="5.3.31"
VAADIN_VER="7.7.17"

download_if_missing() {
    local url="$1" file="$2"
    if [ ! -f "$file" ]; then
        echo "Downloading $file..."
        curl -sL --ssl-no-revoke "$url" -o "$file"
    fi
}

# Commons Collections 3.x (CC1,CC3,CC5,CC6,CC7 chains)
download_if_missing "$MAVEN/commons-collections/commons-collections/$CC3_VER/commons-collections-$CC3_VER.jar" \
    "commons-collections-$CC3_VER.jar"

# Commons Collections 4.x (CC2,CC4 chains)
download_if_missing "$MAVEN/org/apache/commons/commons-collections4/$CC4_VER/commons-collections4-$CC4_VER.jar" \
    "commons-collections4-$CC4_VER.jar"

# Commons BeanUtils (CB1 chain)
download_if_missing "$MAVEN/commons-beanutils/commons-beanutils/$CB_VER/commons-beanutils-$CB_VER.jar" \
    "commons-beanutils-$CB_VER.jar"

# Commons Logging (BeanUtils dependency)
download_if_missing "$MAVEN/commons-logging/commons-logging/$COMMONS_LOG_VER/commons-logging-$COMMONS_LOG_VER.jar" \
    "commons-logging-$COMMONS_LOG_VER.jar"

# Gson (JSON parsing for IR)
download_if_missing "$MAVEN/com/google/code/gson/gson/$GSON_VER/gson-$GSON_VER.jar" \
    "gson-$GSON_VER.jar"

# ASM (for Java Agent bytecode instrumentation)
download_if_missing "$MAVEN/org/ow2/asm/asm/$ASM_VER/asm-$ASM_VER.jar" \
    "asm-$ASM_VER.jar"
download_if_missing "$MAVEN/org/ow2/asm/asm-commons/$ASM_VER/asm-commons-$ASM_VER.jar" \
    "asm-commons-$ASM_VER.jar"

# ── Extended gadget libraries (JDD: ROME, Groovy, Hibernate, etc.) ──

# ROME 1.0 (ToStringBean, ObjectBean, EqualsBean chains)
download_if_missing "$MAVEN/rome/rome/$ROME_VER/rome-$ROME_VER.jar" \
    "rome-$ROME_VER.jar"

# Groovy 2.4 (MethodClosure, GStringImpl chains)
download_if_missing "$MAVEN/org/codehaus/groovy/groovy/$GROOVY_VER/groovy-$GROOVY_VER.jar" \
    "groovy-$GROOVY_VER.jar"

# Hibernate Core 5.6 (TypedValue, ComponentType, GetterMethodImpl chains)
download_if_missing "$MAVEN/org/hibernate/hibernate-core/$HIBERNATE_VER/hibernate-core-$HIBERNATE_VER.jar" \
    "hibernate-core-$HIBERNATE_VER.jar"

# BeanShell 2.0b5 (XThis$Handler, Interpreter chains)
download_if_missing "$MAVEN/org/beanshell/bsh/$BEANSHELL_VER/bsh-$BEANSHELL_VER.jar" \
    "bsh-$BEANSHELL_VER.jar"

# Spring Beans 5.3 (AbstractBeanFactoryPointcutAdvisor)
download_if_missing "$MAVEN/org/springframework/spring-beans/$SPRING_BEANS_VER/spring-beans-$SPRING_BEANS_VER.jar" \
    "spring-beans-$SPRING_BEANS_VER.jar"

# Vaadin Server (MethodProperty, NestedMethodProperty chains)
download_if_missing "$MAVEN/com/vaadin/vaadin-server/$VAADIN_VER/vaadin-server-$VAADIN_VER.jar" \
    "vaadin-server-$VAADIN_VER.jar"

# Classpath separator
SEP=";"
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
    SEP=":"
fi

GADGET_CP="commons-collections-$CC3_VER.jar${SEP}commons-collections4-$CC4_VER.jar${SEP}commons-beanutils-$CB_VER.jar${SEP}commons-logging-$COMMONS_LOG_VER.jar"
EXTENDED_CP="rome-$ROME_VER.jar${SEP}groovy-$GROOVY_VER.jar${SEP}hibernate-core-$HIBERNATE_VER.jar${SEP}bsh-$BEANSHELL_VER.jar${SEP}spring-beans-$SPRING_BEANS_VER.jar${SEP}vaadin-server-$VAADIN_VER.jar"
TOOL_CP="gson-$GSON_VER.jar"
AGENT_CP="asm-$ASM_VER.jar${SEP}asm-commons-$ASM_VER.jar"
FULL_CP="${GADGET_CP}${SEP}${EXTENDED_CP}${SEP}${TOOL_CP}${SEP}${AGENT_CP}"

echo "Compiling DeserTarget.java..."
javac -encoding UTF-8 -cp "$FULL_CP" DeserTarget.java

echo "Compiling DeserAgent.java..."
javac -encoding UTF-8 -cp "$AGENT_CP" DeserAgent.java

# Package agent JAR with manifest — bundle ASM classes so agent is self-contained
echo "Packaging deser_agent.jar..."
echo "Premain-Class: DeserAgent" > MANIFEST.MF
echo "Can-Retransform-Classes: true" >> MANIFEST.MF
echo "Boot-Class-Path: deser_agent.jar" >> MANIFEST.MF
# jar might not be on PATH if only javapath shims are present
JAR_CMD="jar"
if ! command -v jar &>/dev/null; then
    JAR_CMD="/c/Program Files/Java/jdk-17/bin/jar"
    if [ ! -f "$JAR_CMD" ]; then
        echo "ERROR: jar not found. Set JAVA_HOME or add JDK bin to PATH."
        exit 1
    fi
fi
# Extract ASM classes into temp dir, then bundle with agent classes
AGENT_TMP="agent_build_tmp"
rm -rf "$AGENT_TMP"
mkdir -p "$AGENT_TMP"
cd "$AGENT_TMP"
"$JAR_CMD" xf "../asm-$ASM_VER.jar"
"$JAR_CMD" xf "../asm-commons-$ASM_VER.jar"
rm -rf META-INF
cp ../DeserAgent*.class .
cd ..
"$JAR_CMD" cfm deser_agent.jar MANIFEST.MF -C "$AGENT_TMP" .
rm -rf "$AGENT_TMP"
rm -f MANIFEST.MF

echo ""
echo "Compiling IOCD analyzer..."
mkdir -p iocd_classes
javac -encoding UTF-8 -cp "${TOOL_CP}${SEP}${AGENT_CP}" -d iocd_classes iocd/*.java
echo "IOCD analyzer compiled."

echo ""
echo "Build complete."
echo ""
echo "Run targets:"
echo "  # Mixed classpath with CC3 serialization enabled"
echo "  java -Dorg.apache.commons.collections.enableUnsafeSerialization=true \\"
echo "       -javaagent:deser_agent.jar -cp \"$FULL_CP${SEP}.\" DeserTarget --persistent --classpath mixed"
echo ""
echo "  # CC4 with JEP 290 filter"
echo "  java -Dorg.apache.commons.collections.enableUnsafeSerialization=true \\"
echo "       -javaagent:deser_agent.jar -cp \"$FULL_CP${SEP}.\" DeserTarget --persistent --classpath cc4 --filter jep290"
echo ""
echo "  # Run IOCD static analysis to discover gadget chains"
echo "  java -cp \"iocd_classes${SEP}$TOOL_CP${SEP}$AGENT_CP\" \\"
echo "       iocd.IOCDAnalyzer --jars \"$GADGET_CP${SEP}$EXTENDED_CP\" --output ../deser_seeds/iocd/ --verbose"
