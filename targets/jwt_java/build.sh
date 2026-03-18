#!/bin/bash
# Build script for Java JWT differential targets
# Downloads nimbus-jose-jwt, auth0 java-jwt, jjwt + dependencies

set -e
cd "$(dirname "$0")"

MAVEN="https://repo1.maven.org/maven2"

download_if_missing() {
    local url="$1"
    local file="$2"
    if [ ! -f "$file" ]; then
        echo "Downloading $file..."
        curl -sL "$url" -o "$file"
    fi
}

# nimbus-jose-jwt (most popular Java JWT — used by Spring Security)
download_if_missing "$MAVEN/com/nimbusds/nimbus-jose-jwt/9.37.3/nimbus-jose-jwt-9.37.3.jar" \
    "nimbus-jose-jwt-9.37.3.jar"
# nimbus deps
download_if_missing "$MAVEN/net/minidev/json-smart/2.5.0/json-smart-2.5.0.jar" \
    "json-smart-2.5.0.jar"
download_if_missing "$MAVEN/net/minidev/accessors-smart/2.5.0/accessors-smart-2.5.0.jar" \
    "accessors-smart-2.5.0.jar"
download_if_missing "$MAVEN/org/ow2/asm/asm/9.6/asm-9.6.jar" \
    "asm-9.6.jar"

# auth0 java-jwt
download_if_missing "$MAVEN/com/auth0/java-jwt/4.4.0/java-jwt-4.4.0.jar" \
    "java-jwt-4.4.0.jar"

# jjwt (io.jsonwebtoken)
download_if_missing "$MAVEN/io/jsonwebtoken/jjwt-api/0.12.5/jjwt-api-0.12.5.jar" \
    "jjwt-api-0.12.5.jar"
download_if_missing "$MAVEN/io/jsonwebtoken/jjwt-impl/0.12.5/jjwt-impl-0.12.5.jar" \
    "jjwt-impl-0.12.5.jar"
download_if_missing "$MAVEN/io/jsonwebtoken/jjwt-jackson/0.12.5/jjwt-jackson-0.12.5.jar" \
    "jjwt-jackson-0.12.5.jar"

# Jackson (required by jjwt-jackson and auth0 java-jwt)
download_if_missing "$MAVEN/com/fasterxml/jackson/core/jackson-core/2.17.0/jackson-core-2.17.0.jar" \
    "jackson-core-2.17.0.jar"
download_if_missing "$MAVEN/com/fasterxml/jackson/core/jackson-databind/2.17.0/jackson-databind-2.17.0.jar" \
    "jackson-databind-2.17.0.jar"
download_if_missing "$MAVEN/com/fasterxml/jackson/core/jackson-annotations/2.17.0/jackson-annotations-2.17.0.jar" \
    "jackson-annotations-2.17.0.jar"

# Gson (for our JSON output)
download_if_missing "$MAVEN/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar" \
    "gson-2.11.0.jar"

# Build classpath
CP="nimbus-jose-jwt-9.37.3.jar;json-smart-2.5.0.jar;accessors-smart-2.5.0.jar;asm-9.6.jar"
CP="$CP;java-jwt-4.4.0.jar"
CP="$CP;jjwt-api-0.12.5.jar;jjwt-impl-0.12.5.jar;jjwt-jackson-0.12.5.jar"
CP="$CP;jackson-core-2.17.0.jar;jackson-databind-2.17.0.jar;jackson-annotations-2.17.0.jar"
CP="$CP;gson-2.11.0.jar"

if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "cygwin" && "$OSTYPE" != "win32" ]]; then
    CP="${CP//;/:}"
fi

echo "Compiling Java JWT targets..."
javac -cp "$CP" JwtNimbus.java
javac -cp "$CP" JwtAuth0.java
javac -cp "$CP" JwtJjwt.java

echo "Build complete."
echo "  java -cp \"$CP;.\" JwtNimbus <input_file>"
echo "  java -cp \"$CP;.\" JwtAuth0 <input_file>"
echo "  java -cp \"$CP;.\" JwtJjwt <input_file>"
