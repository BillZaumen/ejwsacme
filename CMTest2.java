import java.io.File;
import org.bzdev.ejws.*;

public class CMTest2 {
    public static void main(String argv[]) throws Exception {

	System.out.println("acme.log = " +
			   System.getProperty("acme.log"));

	System.out.println("Provider names: ");
	for (String s: CertManager.providerNames()) {
	    System.out.println("... " + s);
	}

	EmbeddedWebServer ewsHelper = new EmbeddedWebServer(8081);
	File ks = new File("cmkeystore.jks");
	if (ks.exists()) ks.delete();

	/*
	CertManager cm = CertManager.newInstance("default")
	    .setCertName("test")
	    .setDomain("localhost")
	    .setKeystoreFile(ks)
	    .setInterval(0)
	    .setStopDelay(2)
	    .setTracer(System.out)
	    .setCertTrace(true)
	    .setProtocol("TLS")
	    .setEmail("nobody@nobody.com")
	    .setHelper(ewsHelper);

	cm.getSetup();
	*/
	
	CertManager cm = CertManager.newInstance("AcmeClient")
	    .setCertName("test")
	    .setDomain("localhost")
	    .setKeystoreFile(ks)
	    .setInterval(0)
	    .setStopDelay(2)
	    .setTracer(System.out)
	    .setCertTrace(true)
	    .setProtocol("TLS")
	    .setEmail("nobody@nobody.com")
	    .setHelper(ewsHelper)
	    .setMode(CertManager.Mode.LOCAL);

	// Used only for a test of CertManager methods, so it uses
	// HTTP instead of HTTPS.
	EmbeddedWebServer ews = new EmbeddedWebServer(8080);

	cm.getSetup();
	cm.startMonitoring(ews);
	Thread.currentThread().sleep(150000);
	cm.alwaysCreate(true);
	Thread.currentThread().sleep(150000);
	cm.stopMonitoring();

    }
}
