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
import org.apache.tools.ant.types.FileSet;

/**
 * Ant task for signing files with Authenticode.
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class JsignTask extends Task {

    /** The file to be signed. */
    private File file;

    /** The set of files to be signed. */
    private FileSet fileset;

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

    /** The file containing the private key (PEM or PVK format) */
    private File keyfile;

    /** The password for the key in the store (if different from the keystore password) or in the keyfile. */
    private String keypass;

    /** The URL of the timestamping authority. */
    private String tsaurl;

    /** The protocol used for  the timestamping */
    private String tsmode;

    /** The number of retries for timestamping */
    private int tsretries = -1;

    /** The number of seconds to wait between timestamping retries */
    private int tsretrywait = -1;

    /** Tells if previous signatures should be replaced */
    private boolean replace;

    /** The encoding of the script to be signed (UTF-8 by default). */
    private String encoding = "UTF-8";

    /** Tells if a detached signature should be generated or reused. */
    private boolean detached;

    public void setFile(File file) {
        this.file = file;
    }

    public void addFileset(FileSet fileset) {
        this.fileset = fileset;
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

    public void setTsretries(int tsretries) {
        this.tsretries = tsretries;
    }

    public void setTsretrywait(int tsretrywait) {
        this.tsretrywait = tsretrywait;
    }

    public void setReplace(boolean replace) {
        this.replace = replace;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    public void setDetached(boolean detached) {
        this.detached = detached;
    }

    @Override
    public void execute() throws BuildException {
        try {
            SignerHelper helper = new SignerHelper(new AntConsole(this), "attribute");
            
            helper.name(name);
            helper.url(url);
            helper.alg(algorithm);
            helper.keystore(keystore);
            helper.storepass(storepass);
            helper.storetype(storetype);
            helper.alias(alias);
            helper.certfile(certfile);
            helper.keyfile(keyfile);
            helper.keypass(keypass);
            helper.tsaurl(tsaurl);
            helper.tsmode(tsmode);
            helper.tsretries(tsretries);
            helper.tsretrywait(tsretrywait);
            helper.replace(replace);
            helper.encoding(encoding);
            helper.detached(detached);

            if (fileset != null) {
                for(String fileElement : fileset.getDirectoryScanner().getIncludedFiles()) {
                    helper.sign(new File(fileset.getDir(), fileElement));
                }
            } else {
                helper.sign(file);
            }
        } catch (Exception e) {
            throw new BuildException(e.getMessage(), e, getLocation());
        }
    }
}
