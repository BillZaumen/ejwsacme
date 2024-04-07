JFILES = src/org.bzdev.acme/module-info.java \
	src/org.bzdev.acme/org/bzdev/acme/AcmeManager.java

DOCKER_VERSION = 17-jdk-alpine

acme-manager.jar: $(JFILES) /usr/share/bzdev/libbzdev-ejws.jar
	rm -rf mods/org.bzdev.acme
	mkdir -p mods/org.bzdev.acme
	javac -d mods/org.bzdev.acme -p /usr/share/bzdev $(JFILES)
	mkdir -p mods/org.bzdev.acme/META-INF/services
	cp src/org.bzdev.acme/META-INF/services/* \
		mods/org.bzdev.acme/META-INF/services
	jar --create --file acme-manager.jar -C mods/org.bzdev.acme .

acme_client.jar:
	wget -O acme_client.jar \
	https://github.com/porunov/acme_client/releases/download/v3.0.1/acme_client.jar

docker: acme_client.jar
	mkdir -p tmp
	cp /usr/share/bzdev/libbzdev-base.jar tmp
	cp /usr/share/bzdev/libbzdev-ejws.jar tmp
	dpkg-query -f '$${Version}\n' -W libbzdev-ejws-java > tmp/EJWS_VERSION
	docker build --no-cache=true \
		--tag wtzbzdev/ejwsacme:$(DOCKER_VERSION) .
	rm -rf tmp

docker-release:
	docker push wtzbzdev/ejwsacme:$(DOCKER_VERSION)

check:
	docker run -it --name check wtzbzdev/ejwsacme:$(DOCKER_VERSION) sh

test:
	docker run -it --name test -e URL=https://`hostname`:14000/dir \
		wtzbzdev/ejwsacme:test sh

config-test: pebble-roots.pem pebble-intermediates.pem
	docker cp pebble-roots.pem test:/certificates/pebble-roots.pem
	docker cp pebble-intermediates.pem \
		test:/certificates/pebble-intermediates.pem

pebble-roots.pem:	
	wget --no-check-certificate -O pebble-roots.pem \
		https://localhost:15000/roots/0

pebble-intermedates.pem:
	wget --no-check-certificate -O pebble-intermediates.pem \
		https://localhost:15000/intermediates/0


cmtest: acme-manager.jar
	javac -p acme-manager.jar:/usr/share/bzdev \
		--add-modules org.bzdev.ejws \
		CMTest.java
	java -p acme-manager.jar:/usr/share/bzdev --add-modules org.bzdev.ejws \
		CMTest
