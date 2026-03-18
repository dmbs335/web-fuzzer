#!/bin/bash
# Build script for GraphQL Java target
# Downloads graphql-java + dependencies and compiles the target

set -e
cd "$(dirname "$0")"

GRAPHQL_JAVA_VER="22.3"
EXTENDED_SCALARS_VER="22.0"
SLF4J_VER="2.0.16"
REACTIVE_STREAMS_VER="1.0.4"

# Maven Central base
MAVEN="https://repo1.maven.org/maven2"

download_if_missing() {
    local url="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "Downloading $file..."
        curl -sL "$url" -o "$file"
    fi
}

# graphql-java
download_if_missing "$MAVEN/com/graphql-java/graphql-java/$GRAPHQL_JAVA_VER/graphql-java-$GRAPHQL_JAVA_VER.jar" \
    "graphql-java-$GRAPHQL_JAVA_VER.jar"

# graphql-java-extended-scalars (for DateTime, Json scalars)
download_if_missing "$MAVEN/com/graphql-java/graphql-java-extended-scalars/$EXTENDED_SCALARS_VER/graphql-java-extended-scalars-$EXTENDED_SCALARS_VER.jar" \
    "graphql-java-extended-scalars-$EXTENDED_SCALARS_VER.jar"

# SLF4J (required by graphql-java)
download_if_missing "$MAVEN/org/slf4j/slf4j-api/$SLF4J_VER/slf4j-api-$SLF4J_VER.jar" \
    "slf4j-api-$SLF4J_VER.jar"
download_if_missing "$MAVEN/org/slf4j/slf4j-nop/$SLF4J_VER/slf4j-nop-$SLF4J_VER.jar" \
    "slf4j-nop-$SLF4J_VER.jar"

# Reactive streams (required by graphql-java)
download_if_missing "$MAVEN/org/reactivestreams/reactive-streams/$REACTIVE_STREAMS_VER/reactive-streams-$REACTIVE_STREAMS_VER.jar" \
    "reactive-streams-$REACTIVE_STREAMS_VER.jar"

# Compile
CP="graphql-java-$GRAPHQL_JAVA_VER.jar;graphql-java-extended-scalars-$EXTENDED_SCALARS_VER.jar;slf4j-api-$SLF4J_VER.jar;slf4j-nop-$SLF4J_VER.jar;reactive-streams-$REACTIVE_STREAMS_VER.jar"
# Use : separator on non-Windows
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
    CP="${CP//;/:}"
fi

echo "Compiling GraphqlJava.java..."
javac -cp "$CP" GraphqlJava.java

echo "Build complete. Run with:"
echo "  java -cp \"$CP;.\" GraphqlJava <input_file>"
echo "  java -cp \"$CP;.\" GraphqlJava --persistent"
