package org.bzdev.acme;

import java.io.File;
import java.io.FileOutputStream;
import java.io.Flushable;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

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

// See
// https://community.letsencrypt.org/t/tutorial-java-keystores-jks-with-lets-encrypt/34754
// for a description of how to use Java keytool with Let's Encrypt.


public class AcmeManager extends CertManager {
    public AcmeManager() {
    }
    
    private static final int DAY = 3600*24;
    private static final int validity = 90; // Certificates valid for 90 days

    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String SERVERCERT = "servercert";

    private String server() {
	switch(getMode()) {
	case NORMAL:
	    return "https://acme-v02.api.letsencrypt.org/directory";
	case STAGED:
	    return "https://acme-staging-v02.api.letsencrypt.org/directory";
	case LOCAL:
	case TEST:
	    // For LOCAL and TEST, we don't run ACME
	    return "[no server]";

	}
	throw new UnexpectedExceptionError();
    }

    static final String PATHSEP = System.getProperty("file.separator");
    static final String KEYTOOL = System.getProperty("java.home")
		+ PATHSEP + "bin" + PATHSEP + "keytool";



    // private static String server = "https://" + System.getenv("HOSTNAME")
    // + ":14000/dir";

    //
    // Use system properties for testing outside a container so we
    // won't need to be root.
    //
    private static final String ACME_MANAGER_LOG =
	System.getProperty("acme.log", "/var/log/cert/cert.log");
    
    private static final String ETC_ACME =
	System.getProperty("acme.dir", "/etc/acme") + "/";

    private static final String TMP =
	System.getProperty("acme.tmp", "/tmp") + "/";

    private static final String CHALLENGE_DIR =
	System.getProperty("acme.challenge.dir", "/var/www.well-known") + "/";


    private static File log = new File(ACME_MANAGER_LOG);

    // set to true for initial testing
    // private static final boolean TEST = true;

    private boolean runProgram(String... command) {
	CertManager.Mode mode = getMode();
	if (mode == CertManager.Mode.TEST) return true;
	if (mode == CertManager.Mode.LOCAL) {
	    try {
		OutputStream os = new FileOutputStream(log, true);
		PrintWriter w = new PrintWriter(os, true, UTF8);
		boolean start = true;
		for (String arg: command) {
		    if (start && arg.equals("echo")) {
			start = false;
			continue;
		    }
		    w.print(arg);
		    w.print(" ");
		    start = false;
		}
		w.println();
		w.flush();
		w.close();
	    } catch (IOException eio) {
		System.err.println("could not open/write to " + log);
	    }
	    if (command.length > 0 && command[0].equals("echo")) {
		return true;
	    }
	}

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
	CertManager.Mode mode = getMode();
	if (mode == CertManager.Mode.TEST
	    || mode == CertManager.Mode.LOCAL) {
	    arguments.add("echo");
	}
	arguments.add("java");
	arguments.add("-jar");
	arguments.add("acme_client.jar");
	arguments.add("-u");
	arguments.add(server());
	for (String arg: args) {
	    arguments.add(arg);
	}
	try {
	    ProcessBuilder pb = new ProcessBuilder(arguments);
	    if (mode == CertManager.Mode.TEST) {
		pb.redirectErrorStream(true);
	    }else if( mode == CertManager.Mode.LOCAL) {
		pb.redirectErrorStream(true)
		    .redirectOutput(ProcessBuilder.Redirect.appendTo(log));
	    }
	    Process p = pb.start();
	    if (mode == CertManager.Mode.TEST
		|| mode == CertManager.Mode.LOCAL) {
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
	CertManager.Mode mode = getMode();
	if (mode == CertManager.Mode.TEST) return true;
	try {
	    boolean status;
	    char[] carray = getKeystorePW();
	    String spw = (carray == null)? null: new String(carray);
	    char[] carray2 = getKeyPW();
	    String kpw = (carray2 == null)? spw: new String(carray);
	    
	    if (getMode() == CertManager.Mode.LOCAL) {
		// just leave a self-signed certificate in the keystore.
		runProgram("echo", "would have run", KEYTOOL,
			    "-importcert", "-noprompt",
			   "-keystore",
			   getKeystoreFile().getCanonicalPath(),
			   "-alias", SERVERCERT,
			   "-storepass", spw,
			   "-file", ETC_ACME + "certdir/fullchain.pem");
		status = true;
	    } else {
		status = runProgram(KEYTOOL, "-importcert", "-noprompt",
				    "-keystore",
				    getKeystoreFile().getCanonicalPath(),
				    "-alias", SERVERCERT,
				    "-storepass", spw,
				    "-file",
				    ETC_ACME + "certdir/fullchain.pem");
	    }
	    if (status == false) {
		logError("keytool", "failed to import certificate");
		return status;
	    }
	    if (mode != CertManager.Mode.LOCAL) {
		status = runProgram("rm", TMP + "server.p12");
		if (status == false) {
		    logError("rm", "cannot remove " + TMP + "server.p12");
		    return status;
		}
	    }
	    return status;
	} catch (Exception eio) {
	    logError(eio);
	    return false;
	}
    }

    // create the CSR, and if necessary the keystore and a new
    // key pair.
    private boolean createCSR()  {
	String keystoreFile;
	try {
	    File ksFile = getKeystoreFile();
	    if (ksFile == null) {
		logError("create keypair", "keystore file not provided");
		return false;
	    }
	    keystoreFile = ksFile.getCanonicalPath();
	} catch (IOException eio) {
	    logError(eio);
	    return false;
	}
	String domain = getDomain();
	String keypass = new String(getKeyPW());
	String storepass = new String(getKeystorePW());
	reqstatus = runProgram(KEYTOOL, "-genkeypair", "-keyalg", "EC",
			       "-groupname", "secp256r1",
			       "-keystore", keystoreFile,
			       "-alias", SERVERCERT,
			       "-keypass", keypass, "-storepass", storepass,
			       "-dname", "CN="+domain, "-validity", "90");
	if (reqstatus == false) {
	    logError("keytool", "cannot create key pair");
	    return false;
	}
	reqstatus = runProgram(KEYTOOL, "-certreq", "-alias", SERVERCERT,
			       "-file", ETC_ACME + getDomain() + ".csr",
			       "-keystore", keystoreFile,
			       "-storepass", storepass,
			       "-ext", "san=dns:"+domain);
	if (reqstatus == false) {
	    logError("keytool", "cannot create certificate request");
	    return false;
	}
	return true;
    }


    private boolean needCert() {
	if (getMode() == CertManager.Mode.TEST) return false;
	CertManager.Mode mode = getMode();
	boolean status = false;
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
		    // We want the selfSigned test when ACME is actually
		    // being used. The test is so we will delete any
		    // self-signed certificates created for testing when
		    // we are getting the certificate from Lets Encrypt.
		    boolean modeTest = mode != CertManager.Mode.TEST
			&& mode != CertManager.Mode.LOCAL;
		    boolean selfSigned = (chain.length == 1) && modeTest;
		    boolean ok = selfSigned || alwaysCreate();
		    if (3*tdiff <= validity || ok) {
			doDelete();
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

    private void doDelete() {
	File ks = getKeystoreFile();
	if (ks.exists()) {
	    char[] carray = getKeystorePW();
	    String spw = (carray == null)? null: new String(carray);
	    char[] carray2 = getKeyPW();
	    try {
		ProcessBuilder pb = new
		    ProcessBuilder(KEYTOOL,
				   "-delete",
				   "-keystore",
				   ks.getCanonicalPath(),
				   "-storepass", spw,
				   "-alias", SERVERCERT);
		pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
		pb.redirectError(ProcessBuilder.Redirect.DISCARD);
		Process p = pb.start();
		p.waitFor();
	    } catch (Exception e) {
		// ignore - nothing to delete or operation canceled
	    }
	}
    }

    boolean reqstatus = false;


    @Override
    public int helperPort() {
	return getMode() == CertManager.Mode.TEST? 8081: 80;
    }

    @Override
    protected void configureHelper(EmbeddedWebServer ews) {
	File cfile = new File(CHALLENGE_DIR + "acme-challenge");
	cfile.mkdirs();
	try {
	    ews.add("/.well-known/acme-challenge/", DirWebMap.class, cfile,
		    null, true, false, true);
	} catch (Exception e) {}
    }


    @Override
    protected void requestCertificate() {

	File adir = new File (ETC_ACME);
	adir.mkdirs();
	File  tdir = new File(TMP);
	tdir.mkdirs();
	File wdir = new File(ETC_ACME + "workdir");
	wdir.mkdirs();
	File cdir = new File(ETC_ACME + "certdir");
	cdir.mkdirs();

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

	String accountFilename = ETC_ACME + "account.key";
	File accountFile = new File(accountFilename);

	if (!accountFile.exists()) {
	    reqstatus = runProgram("openssl", "genrsa", "-out",
				   accountFilename, "2048");
	    if (reqstatus == false) {
		logError("openssl", "cannot create account key pair");
		return;
	    }
	    JSObject result =
		runAcme("--command", "register", "-a", ETC_ACME + "account.key",
			"--with-agreement-update", "--email", getEmail());
	    if (result.get("status", String.class).equals("error")) {
		reqstatus = false;
		logError("register", result);
		accountFile.delete();
		return;
	    }
	}

	reqstatus = createCSR();
	if (reqstatus == false) {
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
	
	    // order
	    JSObject result = runAcme("--command", "order-certificate",
				      "-a", ETC_ACME + "account.key",
				      "-w", ETC_ACME + "workdir/",
				      "-c", ETC_ACME + getDomain() + ".csr",
				      "--well-known-dir",
				      CHALLENGE_DIR + "acme-challenge",
				      "--one-dir-for-well-known",
				      "--challenge-type", "HTTP01",
				      "--with-agreement-update");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		logError("order-certificate", result);
		reqstatus = false;
		if (unconfigedEWS) ews.shutdown(0);
		return;
	    }
	    // verify
	    result = runAcme("--command", "verify-domains",
			     "-a", ETC_ACME + "account.key",
			     "-w", ETC_ACME + "workdir/",
			     "-c", ETC_ACME + getDomain() + ".csr",
			     "--challenge-type", "HTTP01",
			     "--with-agreement-update");

	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		reqstatus = false;
		logError("verify-domains", result);
		if (unconfigedEWS) ews.shutdown(0);
		return;
	    }
	    // generate and download
	    result = runAcme("--command", "generate-certificate",
			     "-a", ETC_ACME + "account.key",
			     "-w", ETC_ACME + "workdir/",
			     "-c", ETC_ACME + getDomain() + ".csr",
			     "--cert-dir", ETC_ACME + "certdir/",
			     "--with-agreement-update");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		reqstatus = false;
		logError("generate-certificate", result);
		if (unconfigedEWS) ews.shutdown(0);
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

	    if (needCert() == false) {
		renewStatus = false;
		return;
	    }

	    getTracer().append("creating new certificate\n");
	    if (createCSR() == false) {
		renewStatus = false;
		return;
	    }
	    JSObject result =
		runAcme("--command", "order-certificate",
			"-a", ETC_ACME + "account.key",
			"-w", ETC_ACME + "workdir/",
			"-c", ETC_ACME + getDomain() + ".csr",
			"--well-known-dir",
			CHALLENGE_DIR + "acme-challenge",
			"--one-dir-for-well-known",
			"--challenge-type", "HTTP01",
			"--with-agreement-update");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		renewStatus = false;
		logError("order-certificate", result);
		if (ews != null && unconfigedEWS) ews.shutdown(0);
		return;
	    }
	    // verify
	    result = runAcme("--command", "verify-domains",
			     "-a", ETC_ACME + "account.key",
			     "-w", ETC_ACME + "workdir/",
			     "-c", ETC_ACME + getDomain() + ".csr",
			     "--challenge-type", "HTTP01",
			     "--with-agreement-update");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		renewStatus = false;
		logError("verify-domains", result);
		if (ews != null && unconfigedEWS) ews.shutdown(0);
		return;
	    }

	    // generate and download
	    result = runAcme("--command", "generate-certificate",
			     "-a", ETC_ACME + "account.key",
			     "-w", ETC_ACME + "workdir/",
			     "-c", ETC_ACME + getDomain() + ".csr",
			     "--cert-dir",  ETC_ACME + "certdir/",
			     "--with-agreement-update");
	    if (result == null
		|| result.get("status", String.class).equals("error")) {
		renewStatus = false;
		logError("order-certificate", result);
		if (ews != null && unconfigedEWS) {
		    ews.shutdown(0);
		}
		return;
	    }
	    if (ews != null && unconfigedEWS) {
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
