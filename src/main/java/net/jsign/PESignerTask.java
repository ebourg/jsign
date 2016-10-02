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

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

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
    private String storetype;

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
        try {
            PESignerBuilder builder = new PESignerBuilder(new AntConsole(this));
            
            builder.name(name);
            builder.url(url);
            builder.alg(algorithm);
            builder.keystore(keystore);
            builder.storepass(storepass);
            builder.storetype(storetype);
            builder.alias(alias);
            builder.certfile(certfile);
            builder.keyfile(keyfile);
            builder.keypass(keypass);
            builder.tsaurl(tsaurl);
            builder.tsmode(tsmode);
            
            PESigner signer = builder.build();
            signer.sign(file);
        } catch (Exception e) {
            throw new BuildException(e.getMessage(), e);
        }
    }
}
