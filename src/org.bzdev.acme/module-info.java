
module org.bzdev.acme {
    exports org.bzdev.acme;
    requires org.bzdev.ejws;
    requires org.bzdev.base;
    requires java.base;
    provides org.bzdev.ejws.CertManager
	with org.bzdev.acme.AcmeManager;
}
