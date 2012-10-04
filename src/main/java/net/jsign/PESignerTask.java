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

import net.jsign.pe.PEFile;
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

    /** The URL of the timestamping authority. */
    private String tsaurl;

    /** The alias of the certificate in the keystore. */
    private String alias;

    /** The keystore file. */
    private File keystore;

    /** The password for the keystore. */
    private String storepass;

    /** The type of the keystore. */
    private String storetype = "JKS";

    /** The password for the key in the store, if different from the keystore password. */
    private String keypass;

    public void setFile(File file) {
        this.file = file;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setTsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
    }

    public void setAlias(String alias) {
        this.alias = alias;
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

    public void setKeypass(String keypass) {
        this.keypass = keypass;
    }

    @Override
    public void execute() throws BuildException {
        // some exciting parameter validation...
        if (keystore == null) {
            throw new BuildException("keystore attribute must be set");
        }

        KeyStore ks;
        try {
            ks = KeyStore.getInstance(storetype);
        } catch (KeyStoreException e) {
            throw new BuildException("keystore type '" + storetype + "' is not supported", e);
        }
        
        if (!keystore.exists()) {
            throw new BuildException("The keystore " + keystore + " couldn't be found");
        }

        try {
            ks.load(new FileInputStream(keystore), storepass != null ? storepass.toCharArray() : null);
        } catch (Exception e) {
            throw new BuildException("Unable to load the keystore " + keystore, e);
        }
        
        if (alias == null) {
            throw new BuildException("alias attribute must be set");
        }
        
        Certificate[] chain;
        try {
            chain = ks.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new BuildException(e);
        }
        if (chain == null) {
            throw new BuildException("No certificate found under the alias '" + alias + "' in the keystore " + keystore);
        }
        
        String password = keypass != null ? keypass : storepass;
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) ks.getKey(alias, password != null ? password.toCharArray() : null);
        } catch (Exception e) {
            throw new BuildException("Failed to retrieve the private key from the keystore", e);
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
                .withTimestamping(tsaurl != null)
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
}
