# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY pom.xml .
# Pre-fetch dependencies (cached layer)
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn package -B -DskipTests

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /build/target/parse-echo-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-Xmx256m", "-jar", "app.jar"]
