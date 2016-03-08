/**
 * Copyright 2012 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.util.FileUtils;

/**
 * Ant task for signing executable files.
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PESignerTask extends Task {

    /** The file to be signed. */
    private File file;

    /** The program name embedded in the signature. */
    private String name;

    /** The program URL embedded in the signature. */
    private String url;

    /** The digest algorithm to use for the signature. */
    private String algorithm;

    /** The keystore file. */
    private File keystore;

    /** The password for the keystore. */
    private String storepass;

    /** The type of the keystore. */
    private String storetype = "JKS";

    /** The alias of the certificate in the keystore. */
    private String alias;

    /** The file containing the certificate chain (PKCS#7 format). */
    private File certfile;

    /** The file containing the private key (PVK format) */
    private File keyfile;

    /** The password for the key in the store (if different from the keystore password) or in the keyfile. */
    private String keypass;

    /** The URL of the timestamping authority. */
    private String tsaurl;

    /** The protocol used for  the timestamping */
    private String tsmode;

    public void setFile(File file) {
        this.file = file;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setAlg(String alg) {
        this.algorithm = alg;
    }

    public void setTsmode(String tsmode) {
        this.tsmode = tsmode;
    }

    public void setKeystore(File keystore) {
        this.keystore = keystore;
        
        // guess the type of the keystore from the extension of the file
        String name = keystore.getName().toLowerCase();
        if (name.endsWith(".p12") || name.endsWith(".pfx")) {
            storetype = "PKCS12";
        }
    }

    public void setStorepass(String storepass) {
        this.storepass = storepass;
    }

    public void setStoretype(String storetype) {
        this.storetype = storetype;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void setCertfile(File certfile) {
        this.certfile = certfile;
    }

    public void setKeyfile(File keyfile) {
        this.keyfile = keyfile;
    }

    public void setKeypass(String keypass) {
        this.keypass = keypass;
    }

    public void setTsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
    }

    @Override
    public void execute() throws BuildException {
        PrivateKey privateKey;
        Certificate[] chain;
        
        // some exciting parameter validation...
        if (keystore == null && keyfile == null && certfile == null) {
            throw new BuildException("keystore attribute, or keyfile and certfile attributes must be set");
        }
        if (keystore != null && (keyfile != null || certfile != null)) {
            throw new BuildException("keystore attribute can't be mixed with keyfile or certfile");
        }
        
        if (keystore != null) {
            // JKS or PKCS12 keystore 
            KeyStore ks;
            try {
                ks = KeyStore.getInstance(storetype);
            } catch (KeyStoreException e) {
                throw new BuildException("keystore type '" + storetype + "' is not supported", e);
            }
            
            if (!keystore.exists()) {
                throw new BuildException("The keystore " + keystore + " couldn't be found");
            }
            FileInputStream in = null;
            try {
                in = new FileInputStream(keystore);
                ks.load(in, storepass != null ? storepass.toCharArray() : null);
            } catch (Exception e) {
                throw new BuildException("Unable to load the keystore " + keystore, e);
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
                throw new BuildException("alias attribute must be set");
            }
            
            try {
                chain = ks.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                throw new BuildException(e);
            }
            if (chain == null) {
                throw new BuildException("No certificate found under the alias '" + alias + "' in the keystore " + keystore);
            }
            
            char[] password = keypass != null ? keypass.toCharArray() : storepass.toCharArray();
            
            try {
                privateKey = (PrivateKey) ks.getKey(alias, password);
            } catch (Exception e) {
                throw new BuildException("Failed to retrieve the private key from the keystore", e);
            }
            
        } else {
            // separate private key and certificate files (PVK/SPC)
            if (keyfile == null) {
                throw new BuildException("keyfile attribute must be set");
            }
            if (!keyfile.exists()) {
                throw new BuildException("The keyfile " + keyfile + " couldn't be found");
            }
            if (certfile == null) {
                throw new BuildException("certfile attribute must be set");
            }
            if (!certfile.exists()) {
                throw new BuildException("The certfile " + certfile + " couldn't be found");
            }
            
            // load the certificate chain
            try {
                chain = loadCertificateChain(certfile);
            } catch (Exception e) {
                throw new BuildException("Failed to load the certificate from " + certfile, e);
            }
            
            // load the private key
            try {
                privateKey = PVK.parse(keyfile, keypass);
            } catch (Exception e) {
                throw new BuildException("Failed to load the private key from " + keyfile, e);
            }
        }

        if (algorithm != null && DigestAlgorithm.of(algorithm) == null) {
            throw new BuildException("The digest algorithm " + algorithm + " is not supported");
        }
        
        if (file == null) {
            throw new BuildException("file attribute must be set");
        }
        if (!file.exists()) {
            throw new BuildException("The file " + file + " couldn't be found");
        }
        
        PEFile peFile;
        try {
            peFile = new PEFile(file);
        } catch (IOException e) {
            throw new BuildException("Couldn't open the executable file " + file, e);
        }
        
        // and now the actual work!
        PESigner signer = new PESigner(chain, privateKey)
                .withProgramName(name)
                .withProgramURL(url)
                .withDigestAlgorithm(DigestAlgorithm.of(algorithm))
                .withTimestamping(tsaurl != null)
                .withTimestampingMode(tsmode != null ? TimestampingMode.of(tsmode) : TimestampingMode.AUTHENTICODE)
                .withTimestampingAutority(tsaurl);


        try {
            log("Adding Authenticode signature to " + FileUtils.getRelativePath(getProject().getBaseDir(), file));
            signer.sign(peFile);
        } catch (Exception e) {
            throw new BuildException("Couldn't sign " + file, e);
        } finally {
            try {
                peFile.close();
            } catch (IOException e) {
                log("Couldn't close " + file, e, Project.MSG_WARN);
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
