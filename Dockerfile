FROM eclipse-temurin:17-jdk-alpine AS build

RUN apk add openssl
COPY acme_client.jar /acme_client.jar

# COPY acme-client-3.1.0-release.zip  /acme-client.zip
# RUN unzip /acme-client.zip && rm /acme-client.zip \
#    && mv /acme-client-* /acme-client

RUN mkdir -p /usr/share/bzdev && mkdir -p /var/log/cert
COPY tmp/libbzdev-base.jar /usr/share/bzdev
COPY tmp/libbzdev-ejws.jar /usr/share/bzdev
COPY acme-manager.jar /usr/share/bzdev/acme-manager.jar
COPY tmp/EJWS_VERSION /EJWS_VERSION

RUN mkdir /certificates

ENV EJWS_ACME_MODULES=org.bzdev.acme,org.bzdev.base,org.bzdev.ejws,\
java.base,java.logging,java.management,\
java.naming,java.sql,java.xml,jdk.crypto.cryptoki,\
jdk.crypto.ec,jdk.localedata

