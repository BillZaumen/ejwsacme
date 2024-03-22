package org.bzdev.acme;

import java.io.File;
import java.io.Flushable;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

import java.io.FileWriter;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.cert.*;
import java.time.Instant;
import java.time.Clock;
import java.util.List;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;

import org.bzdev.ejws.*;
import org.bzdev.ejws.maps.DirWebMap;
import org.bzdev.lang.UnexpectedExceptionError;
import org.bzdev.util.*;

public class AcmeManager extends CertManager {
    public AcmeManager() {
    }
    
    private static final int DAY = 3600*24;
    private static final int validity = 90; // Certificates valid for 90 days

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String SERVERCERT = "servercert";

     /*
    private String server ="https://acme-v02.api.letsencrypt.org/directory";
    
    private String server =
	"https://acme-staging-v02.api.letsencrypt.org/directory";
    private String server ="https://acme-v02.api.letsencrypt.org/directory";
    */

    private String server() {
	switch(getMode()) {
	case NORMAL:
	    return "https://acme-v02.api.letsencrypt.org/directory";
	case STAGED:
	    return "https://acme-staging-v02.api.letsencrypt.org/directory";
	case TEST:
	    return "https://" + System.getenv("HOSTNAME") + ":14000/dir";
	}
	throw new UnexpectedExceptionError();
    }


    // private static String server = "https://" + System.getenv("HOSTNAME")
    // + ":14000/dir";

    private static File log = new File("/cert.log");

    // set to true for initial testing
    // private static final boolean TEST = true;

    private boolean runProgram(String... command) {
	if (getMode() == CertManager.Mode.TEST) return true;
	try {
	    ProcessBuilder pb = (new ProcessBuilder(command))
		.redirectErrorStream(true)
		.redirectOutput(ProcessBuilder.Redirect.appendTo(log));
	    Process p = pb.start();
	    return p.waitFor() == 0;
	} catch (Exception e) {
	    return false;
	}
    }

    private static final Clock clock = Clock.systemDefaultZone();

    private static String getTimestamp() {
	return clock.instant().atZone(clock.getZone()).toString()
	    + ": ";
    }

    private void logError(Exception e) {
	Appendable tracer = getTracer();
	if (tracer != null) {
	    StringBuilder sb = new StringBuilder();
	    sb.append(getTimestamp());
	    String name = e.getClass().getCanonicalName();
	    if (name == null) {
		name = e.getClass().getName();
	    }
	    sb.append(name);
	    sb.append("\n    ");
	    sb.append(e.getMessage());
	    sb.append("\n");
	    try {
		tracer.append(sb.toString());
		if (tracer instanceof Flushable) {
		    ((Flushable) tracer).flush();
		}
	    } catch (IOException eio) {}
	}	
    }

    private void logError(String op, String reason) {
	Appendable tracer = getTracer();
	if (tracer != null) {
	    StringBuilder sb = new StringBuilder();
	    sb.append(getTimestamp());
	    sb.append(op);
	    sb.append((reason == null)? " failed\n": " failed ...\n");
	    if (reason != null) {
		sb.append("    ");
		sb.append(reason);
		sb.append("\n");
	    }
	    try {
		tracer.append(sb.toString());
		if (tracer instanceof Flushable) {
		    ((Flushable) tracer).flush();
		}
	    } catch (IOException eio) {}
	}
    }

    private void logError(String op, JSObject value) {
	Appendable tracer = getTracer();
	if (tracer != null) {
	    StringBuilder sb = new StringBuilder();
	    sb.append(getTimestamp());
	    boolean verbose = value.size() > 1;
	    sb.append(op + (verbose? " failed ...\n": " failed\n"));
	    if (verbose) {
		logError(sb, "    ", value);
	    }
	    try {
		tracer.append(sb.toString());
		if (tracer instanceof Flushable) {
		    ((Flushable) tracer).flush();
		}
	    } catch (IOException eio) {}
	}
    }

    private static void logError(StringBuilder sb,
				 String prefix,
				 JSObject value)
    {
	String newprefix = prefix + "    ";
	for (Map.Entry<String,Object> entry: value.entrySet()) {
	    String key = entry.getKey();
	    if (key.equals("status")) continue;
	    Object v = entry.getValue();
	    sb.append(prefix + key + ": ");
	    if (v == null) {
		sb.append("null\n");
	    } else if (v instanceof JSObject) {
		sb.append("[object] ...\n");
		logError(sb, newprefix, (JSObject) v);
	    } else if (v instanceof JSArray) {
		sb.append("\n");
		logError(sb, newprefix, (JSArray) v);
	    } else {
		sb.append(v.toString());
		sb.append("\n");
	    }
	}
    }

    private static void logError(StringBuilder sb,
				 String prefix,
				 JSArray value)
    {
	String newprefix = prefix + "    ";
	value.forEach((v) -> {
		sb.append(prefix);
		if (v == null) {
		    sb.append("null\n");
		} else if (v instanceof JSArray) {
		    sb.append("[array] ...\n");
		    logError(sb, newprefix, (JSArray) v);
		} else if (v instanceof JSObject) {
		    sb.append("[object] ...\n");
		    logError(sb, newprefix, (JSObject) v);
		} else {
		    sb.append(v.toString());
		    sb.append("\n");
		}
	    });
    }

    private JSObject runAcme(String... args) {
	List<String> arguments = new LinkedList<>();
	if (getMode() == CertManager.Mode.TEST) arguments.add("echo"); //
	arguments.add("java");
	arguments.add("-jar");
	arguments.add("acme_client.jar");
	arguments.add("-u");
	arguments.add(server());
	try {
	    ProcessBuilder pb = new ProcessBuilder(arguments);
	    Process p = pb.start();
	    if (getMode() == CertManager.Mode.TEST) {
		JSObject obj = new JSObject();
		p.waitFor();
		obj.put("status", "ok");
		return obj;
	    }
	    InputStream in = p.getInputStream();
	    Object result = JSUtilities.JSON.parse(in, UTF8);
	    in.transferTo(OutputStream.nullOutputStream());
	    p.waitFor();
	    if (result instanceof JSObject) {
		return (JSObject) result;
	    } else {
		return null;
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	    return null;
	}
    }

    private boolean setupKeystore() {
	if (getCertName() == null) {
	    Appendable tracer = getTracer();
	    if (tracer != null) {
		try {
		    tracer.append("Error: certificate name missing");
		    if (tracer instanceof Flushable) {
			((Flushable) tracer).flush();
		    }
		} catch (IOException eio) {}
	    }
	    return false;
	}

	if (getMode() == CertManager.Mode.TEST) return true;
	try {
	    boolean status =
		runProgram("openssl", "pkcs12", "-export",
			   "-password", "changeit",
			   "-in", "/etc/acme/certdir/fullchain.pem",
			   "-inkey", "/etc/acme/" + getDomain() + ".key",
			   "-out", "/tmp/server.p12", "-name", getCertName());
	    if (status == false) {
		logError("openssl", "could not export certificate");
		return status;
	    }
	    String pathsep = System.getProperty("file.separator");
	    String keytool = System.getProperty("java.home")
		+ pathsep + "bin" + pathsep + "keytool";
	    status = runProgram(keytool, "-importkeystore",
				"-deststorepass", "changeit",
				"-destkeystore",
				getKeystoreFile().getCanonicalPath(),
				"-srckeystore", "/tmp/server.p12",
				"-srcstoretype", "PKC512",
				"-srcstorepass", "changeit",
				"-alias", SERVERCERT);
	    if (status == false) {
		logError("keytool", "failed to import certificate");
		return status;
	    }
	    status = runProgram("rm", "/tmp/server.p12");
	    if (status == false) {
		logError("rm", "cannot remove /tmp/server.p12");
		return status;
	    }
	    return status;
	} catch (Exception eio) {
	    logError(eio);
	    return false;
	}
    }

    private boolean needCert() {
	if (getMode() == CertManager.Mode.TEST) return false;
	boolean status = false;
	String pathsep = System.getProperty("file.separator");
	String keytool = System.getProperty("java.home")
	    + pathsep + "bin" + pathsep + "keytool";
	char[] carray = getKeystorePW();
	String spw = (carray == null)? null: new String(carray);
	char[] carray2 = getKeyPW();
	String kpw = (carray2 == null)? spw: new String(carray);
	File ks = getKeystoreFile();
	if (ks.exists()) {
	    try {
		KeyStore keystore = KeyStore.getInstance(ks, carray);
		Certificate cert = keystore
		    .getCertificate(SERVERCERT);
		if (cert != null && cert instanceof X509Certificate) {
		    X509Certificate xcert = (X509Certificate) cert;
		    long tdiff = xcert.getNotAfter().getTime()
			- Instant.now().toEpochMilli();
		    tdiff /= (DAY*1000);
		    Certificate[] chain =
			keystore.getCertificateChain(SERVERCERT);
		    boolean selfSigned = (chain.length == 1);
		    if (3*tdiff <= validity || selfSigned) {
			ProcessBuilder pb1 = new
			    ProcessBuilder(keytool,
					   "-delete",
					   "-keystore",
					   ks.getCanonicalPath(),
					   "-storepass", spw,
					   "-alias", SERVERCERT);
			pb1.redirectOutput
			    (ProcessBuilder.Redirect.DISCARD);
			pb1.redirectError
			    (ProcessBuilder.Redirect.DISCARD);
			Process p1 = pb1.start();
			p1.waitFor();
			return true;
		    } else {
			return false;
		    }
		} else {
		    return true;
		}
	    } catch (Exception ke) {
		return true;
	    }
	} else {
	    return true;
	}
    }


    boolean reqstatus = false;


    @Override
    public int helperPort() {
	return getMode() == CertManager.Mode.TEST? 8081: 80;
    }

    @Override
    protected void configureHelper(EmbeddedWebServer ews) {
	File cfile = new File("/var/www.well-known/acme-challenge");
	cfile.mkdirs();
	try {
	    ews.add("/.well-known/acme-challenge/", DirWebMap.class, cfile,
		    null, true, false, true);
	} catch (Exception e) {}
    }


    @Override
    protected void requestCertificate() {

	reqstatus = false;
	try {
	    if(getDomain() == null) {
		Appendable tracer = getTracer();
		if (tracer != null) {
		    try {
			tracer.append("Error: domain missing\n");
			if (tracer instanceof Flushable) {
			    ((Flushable) tracer).flush();
			}
		    } catch (IOException eio) {}
		}
		return;
	    } else if (getEmail() == null) {
		Appendable tracer = getTracer();
		if (tracer != null) {
		    try {
			tracer.append("Error: email address missing\n");
			if (tracer instanceof Flushable) {
			    ((Flushable) tracer).flush();
			}
		    } catch (IOException eio) {}
		}
		return;
	    } else if (getKeystoreFile() == null) {
		Appendable tracer = getTracer();
		if (tracer != null) {
		    tracer.append("Error: keystore file missing\n");
		    if (tracer instanceof Flushable) {
			((Flushable) tracer).flush();
		    }
		}
		return;
	    }
	} catch (IOException eio) {
	    return;
	}

	if (needCert() == false) {
	    // have a certificate that has not expired or is not about
	    // to expire.
	    reqstatus = true;
	    return;
	}

	reqstatus = runProgram("openssl", "ecparam", "-name", "prime256v1",
			       "-genkey", "-noout",
			       "-out", "/etc/acme/account.key");
	if (reqstatus == false) {
	    logError("openssl", "cannot create key pair");
	    return;
	}
	reqstatus = runProgram("openssl", "ecparam", "-name", "prime256v1",
			       "-genkey", "-noout", "-out", "/etc/acme/"
			       + getDomain() + ".key");
	if (reqstatus == false) {
	    logError("openssl", "cannot create key pair");
	    return;
	}
	reqstatus = runProgram("openssl", "req", "-new",
			       "-key", "/etc/acme/" + getDomain() + ".key",
			       "-sha256", "-nodes",
			       "-subj", "CN=" + getDomain(), "-outform", "PEM",
			       "-out", "/etc/acme/" + getDomain() +".csr");
	if (reqstatus == false) {
	    logError("openssl", "cannot create certificate signing request");
	    return;
	}
	// register
	
	JSObject result =
	    runAcme("--command", "register", "-a", "/etc/acme/account.key",
		    "--with-agreement-update", "--email", getEmail());
	if (result.get("status", String.class).equals("error")) {
	    logError("register", result);
	    reqstatus = false;
	    return;
	}
	EmbeddedWebServer ews = getHelper();
	boolean unconfigedEWS = (ews == null);
	try {
	    if (unconfigedEWS) {
		ews = new EmbeddedWebServer(80);
		configureHelper(ews);
		ews.start();
	    }
	    /*
	    File cfile = new File("/var/www.well-known/acme-challenge");
	    cfile.mkdirs();
	    ews.add("/.well-known/acme-challenge/", DirWebMap.class, cfile,
		    null, true, false, true);
	    */
	
	    // order
	    result = runAcme("--command", "order-certificate",
			     "-a", "/etc/acme/account.key",
			     "-w", "/etc/acme/workdir/",
			     "-c", "/etc/acme/" + getDomain() + ".csr",
			     "--well-known-dir",
			     "/var/www.well-known/acme-challenge",
			     "--one-dir-for-well-known",
			     "--challenge-type", "HTTP01");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		logError("order-certificate", result);
		reqstatus = false;
		ews.shutdown(0);
		return;
	    }
	    // verify
	    result = runAcme("--command", "verify-domains",
			     "-a", "/etc/acme/account.key",
			     "-w", "/etc/acme/workdir/",
			     "-c", "/etc/acme/" + getDomain() + ".csr",
			     "--challenge-type", "HTTP01");

	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		reqstatus = false;
		logError("verify-domains", result);
		ews.shutdown(0);
		return;
	    }
	    // generate and download
	    result = runAcme("--command", "generate-certificate",
			     "-a", "/etc/acme/account.key",
			     "-w", "/etc/acme/workdir/",
			     "-c", "/etc/acme/" + getDomain() + ".csr",
			     "--cert-dir /etc/acme/certdir/",
			     "--challenge-type", "HTTP01");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		reqstatus = false;
		logError("generate-certificate", result);
		ews.shutdown(0);
		return;
	    }
	    boolean status = setupKeystore();
	    if (unconfigedEWS) {
		ews.shutdown(0);
	    }
	    reqstatus = status;
	} catch (Exception e) {
	    logError(e);
	    if (ews != null) {
		ews.shutdown(0);
	    }
	    reqstatus = false;
	}
    }

    public String providerName() {
	return "AcmeClient";
    }

    @Override
    protected boolean certificateRequestStatus() {
	return reqstatus;
    }
 
    private boolean renewStatus = false;

    @Override
    protected void requestRenewal() {
	// order

	try {
	    if(getDomain() == null) {
		Appendable tracer = getTracer();
		if (tracer != null) {
		    try {
			tracer.append("Error: domain missing\n");
			if (tracer instanceof Flushable) {
			    ((Flushable) tracer).flush();
			}
		    } catch (IOException eio) {}
		}
		renewStatus = false;
		return;
	    } else if (getKeystoreFile() == null) {
		Appendable tracer = getTracer();
		if (tracer != null) {
		    tracer.append("Error: keystore file missing\n");
		    if (tracer instanceof Flushable) {
			((Flushable) tracer).flush();
		    }
		}
		renewStatus = false;
		return;
	    }
	} catch (IOException eio) {
	    renewStatus = false;
	    return;
	}

	EmbeddedWebServer ews = getHelper();
	boolean unconfigedEWS = (ews == null);
	try {
	    if (unconfigedEWS) {
		ews = new EmbeddedWebServer(80);
		configureHelper(ews);
		ews.start();
	    }
	    /**
	    File cfile = new File("/var/www.well-known/acme-challenge");
	    cfile.mkdirs();
	    ews.add("/.well-known/acme-challenge/", DirWebMap.class, cfile,
		    null, true, false, true);
	    */
	    // ews.start();
	    JSObject result =
		runAcme("--command", "order-certificate",
			"-a", "/etc/acme/account.key",
			"-w", "/etc/acme/workdir/",
			"-c", "/etc/acme/" + getDomain() + ".csr",
			"--well-known-dir",
			"/var/www.well-known/acme-challenge",
			"--one-dir-for-well-known",
			"--challenge-type", "HTTP01");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		renewStatus = false;
		logError("order-certificate", result);
		ews.shutdown(0);
		return;
	    }
	    // verify
	    result = runAcme("--command", "verify-domains",
			     "-a", "/etc/acme/account.key",
			     "-w", "/etc/acme/workdir/",
			     "-c", "/etc/acme/" + getDomain() + ".csr",
			"--challenge-type", "HTTP01");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		renewStatus = false;
		logError("verify-domains", result);
		ews.shutdown(0);
		return;
	    }

	    // generate and download
	    result = runAcme("--command", "order-certificate",
			     "-a", "/etc/acme/account.key",
			     "-w", "/etc/acme/workdir/",
			     "-c", "/etc/acme/" + getDomain() + ".csr",
			     "--cert-dir /etc/acme/certdir/",
			     "--challenge-type", "HTTP01");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		renewStatus = false;
		logError("order-certificate", result);
		if (unconfigedEWS) {
		    ews.shutdown(0);
		}
		return;
	    }
	    if (unconfigedEWS) {
		ews.shutdown(0);
	    }
	    boolean status = setupKeystore();
	    if (status) {
		synchronized(this) {
		    renewStatus = true;
		    this.notifyAll();
		}
	    } else {
		renewStatus = false;
	    }
	} catch (Exception e) {
	    logError(e);
	    if (ews != null && unconfigedEWS) {
		ews.shutdown(0);
	    }
	    renewStatus = false;
	}
    }

    @Override
    protected boolean renewalRequestStatus() throws InterruptedException {
	synchronized(this) {
	    try {
		while (renewStatus == false) {
		    this.wait();
		}
		return true;
	    } catch (InterruptedException e) {
		logError(e);
		renewStatus = false;
		throw e;
	    } finally {
		renewStatus = false;
	    }
	}
    }
}
