package net.jsign;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import net.jsign.pe.PEFile;
import net.jsign.timestamp.TimestampingMode;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

@Mojo(name = "sign")
public class Sign extends AbstractMojo {

    /**
     * The executable file to be signed (Required).
     */
    @Parameter
    private File file;

    /**
     * The name of the application (NOT Required).
     */
    @Parameter
    private String name;

    /**
     * The URL of the application (NOT Required).
     */
    @Parameter
    private String url;

    /**
     * The keystore file (Required, unless certfile and keyfile are specified.).
     */
    @Parameter
    private File keystore;

    /**
     * The password to open the keystore (NOT Required).
     */
    @Parameter
    private String storepass;

    /**
     * The type of the keystore: JKS: Java keystore PKCS12: Standard PKCS#12
     * keystore (.p12 or .pfx files). NOT Required: defaults to "JKS".
     */
    @Parameter(defaultValue = "JKS", required = false)
    private String storetype = "JKS";

    /**
     * The alias of the certificate used for signing in the keystore. Java code
     * signing certificates can be used for Authenticode signatures. Required,
     * if keystore is specified.
     */
    @Parameter
    private String alias;

    /**
     * The file containing the PKCS#7 certificate chain (.p7b or .spc files).
     * Required, unless keystore is specified.
     */
    @Parameter
    private File certfile;

    /**
     * The file containing the private key. Only PVK files are supported.
     * Required, unless keystore is specified.
     */
    @Parameter
    private File keyfile;

    /**
     * The password of the private key. When using a keystore, this parameter
     * can be omitted if the keystore shares the same password (NOT Required).
     */
    @Parameter
    private String keypass;

    /**
     * The URL of the timestamping authority. RFC 3161 servers used for jar
     * signing are not compatible with Authenticode signatures. You can use the
     * COMODO (http://timestamp.comodoca.com/authenticode) or the Verisign
     * (http://timestamp.verisign.com/scripts/timstamp.dll) services (NOT
     * Required).
     */
    @Parameter
    private String tsaurl;

    @Parameter
    private String algorithm;

    @Parameter(defaultValue = "AUTHENTICODE", required = false)
    private String tsmode;

	/** A simple proxy url (format [http://]host:port). */
    @Parameter
	private String proxyUrl;

	/** The user to log on to the proxy. */
    @Parameter
	private String proxyUser;

	/** The password for the proxyUser to log on to the proxy. */
    @Parameter
	private String proxyPassword;

    public void execute() throws MojoExecutionException, MojoFailureException {

        if (keystore != null && keystore.getName() != null) {
            String ksName = keystore.getName().toLowerCase();
            if (ksName.endsWith(".p12") || ksName.endsWith(".pfx")) {
                storetype = "PKCS12";
            }
        }

        // Obtain the log
        Log log = getLog();

        log.debug("Executing " + getClass().getSimpleName());
        log.debug("\tFile: " + file);
        log.debug("\tName: " + name);
        log.debug("\tUrl: " + url);
        log.debug("\tKeystore: " + keystore);
        log.debug("\tStoretype: " + storetype);
        log.debug("\tAlias: " + alias);
        log.debug("\tCertfile: " + certfile);
        log.debug("\tKeyfile: " + keyfile);
        log.debug("\tURL of the timestamping authority: " + tsaurl);

        // Get the project
        MavenProject project = (MavenProject) getPluginContext().get("project");
        File buildDir = new File(project.getBuild().getDirectory());
        log.debug("\tBuild Directory: " + buildDir.getAbsolutePath());

        PrivateKey privateKey;
        Certificate[] chain;

        // some exciting parameter validation...
        if (keystore == null && keyfile == null && certfile == null) {
            throw new MojoFailureException("keystore attribute, or keyfile and certfile attributes must be set");
        }
        if (keystore != null && (keyfile != null || certfile != null)) {
            throw new MojoFailureException("keystore attribute can't be mixed with keyfile or certfile");
        }

        if (keystore != null) {
            // JKS or PKCS12 keystore
            KeyStore ks;
            try {
                ks = KeyStore.getInstance(storetype);
            } catch (KeyStoreException e) {
                throw new MojoFailureException("keystore type '" + storetype + "' is not supported", e);
            }

            if (!keystore.exists()) {
                throw new MojoFailureException("The keystore " + keystore + " couldn't be found");
            }
            FileInputStream in = null;
            try {
                in = new FileInputStream(keystore);
                ks.load(in, storepass != null ? storepass.toCharArray() : null);
            } catch (Exception e) {
                throw new MojoFailureException("Unable to load the keystore " + keystore, e);
            } finally {
                try {
                    if (in != null) {
                        in.close();
                    }
                } catch (IOException e) {
                    // ignore
                }
            }

            if (alias == null) {
                throw new MojoFailureException("alias attribute must be set");
            }

            try {
                chain = ks.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                throw new MojoFailureException("", e);
            }
            if (chain == null) {
                throw new MojoFailureException("No certificate found under the alias '" + alias + "' in the keystore " + keystore);
            }

            char[] password = keypass != null ? keypass.toCharArray() : storepass.toCharArray();

            try {
                privateKey = (PrivateKey) ks.getKey(alias, password);
            } catch (Exception e) {
                throw new MojoFailureException("Failed to retrieve the private key from the keystore", e);
            }

        } else {
            // separate private key and certificate files (PVK/SPC)
            if (keyfile == null) {
                throw new MojoFailureException("keyfile attribute must be set");
            }
            if (!keyfile.exists()) {
                throw new MojoFailureException("The keyfile " + keyfile + " couldn't be found");
            }
            if (certfile == null) {
                throw new MojoFailureException("certfile attribute must be set");
            }
            if (!certfile.exists()) {
                throw new MojoFailureException("The certfile " + certfile + " couldn't be found");
            }

            // load the certificate chain
            try {
                chain = loadCertificateChain(certfile);
            } catch (Exception e) {
                throw new MojoFailureException("Failed to load the certificate from " + certfile, e);
            }

            // load the private key
            try {
                privateKey = PVK.parse(keyfile, keypass);
            } catch (Exception e) {
                throw new MojoFailureException("Failed to load the private key from " + keyfile, e);
            }
        }

        if (algorithm != null && DigestAlgorithm.of(algorithm) == null) {
            throw new MojoFailureException("The digest algorithm " + algorithm + " is not supported");
        }

        if (file == null) {
            throw new MojoFailureException("file attribute must be set");
        }
        if (!file.exists()) {
            throw new MojoFailureException("The file " + file + " couldn't be found");
        }

        PEFile peFile;
        try {
            peFile = new PEFile(file);
        } catch (IOException e) {
            throw new MojoFailureException("Couldn't open the executable file " + file, e);
        }

        // and now the actual work!
        PESigner signer = new PESigner(chain, privateKey).withProgramName(name).withProgramURL(url).withDigestAlgorithm(DigestAlgorithm.of(algorithm)).withTimestamping(tsaurl != null).withTimestampingMode(TimestampingMode.of(tsmode)).withTimestampingAutority(tsaurl);

        try {
            getLog().info("Adding Authenticode signature to " +  file);
            signer.sign(peFile);
        } catch (Exception e) {
            throw new MojoFailureException("Couldn't sign " + file, e);
        } finally {
            try {
                peFile.close();
            } catch (IOException e) {
                getLog().warn("Couldn't close " + file, e);
            }
        }
    }

    /**
     * Load the certificate chain from the specified PKCS#7 files.
     */
    @SuppressWarnings("unchecked")
    private Certificate[] loadCertificateChain(File file) throws IOException, CertificateException {
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<Certificate> certificates = (Collection<Certificate>) certificateFactory.generateCertificates(in);
            return certificates.toArray(new Certificate[certificates.size()]);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

}
