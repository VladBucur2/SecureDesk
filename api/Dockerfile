# syntax=docker/dockerfile:1

# ---- build: compile and run the whole test suite ---------------------------------------------
# A failing test fails the image build, so an API whose authentication cases or authorisation
# matrix fail cannot be deployed (as in the PoCs). The CycloneDX SBOM is made here too (SR-11).
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B package \
 && java -Djarmode=tools -jar target/securedesk-api.jar extract --destination /extracted

# ---- runtime: a JRE on Alpine, an unprivileged user, nothing else -----------------------------
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S -g 10001 securedesk \
 && adduser -S -u 10001 -G securedesk -H -s /sbin/nologin securedesk
WORKDIR /app
COPY --from=build /extracted/ /app/
COPY --from=build /src/target/classes/META-INF/sbom/application.cdx.json /app/sbom/securedesk-api.cdx.json
USER 10001
EXPOSE 8443
# The `migrate` service runs the same image with another entry point (see docker-compose.yml).
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/securedesk-api.jar"]
