# The one-time setup runs in the API's own base image, which already has OpenSSL and keytool,
# so nothing has to be downloaded to generate the laboratory's secrets.
FROM eclipse-temurin:25-jre-alpine
COPY setup.sh /usr/local/bin/setup.sh
ENTRYPOINT ["sh", "/usr/local/bin/setup.sh"]
