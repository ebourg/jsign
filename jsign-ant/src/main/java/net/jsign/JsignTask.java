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
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.BuildLogger;
import org.apache.tools.ant.DefaultLogger;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.FileSet;

import static org.apache.tools.ant.Project.*;

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

    /** The operation to execute */
    private String command = "sign";

    /** The program name embedded in the signature. */
    private String name;

    /** The program URL embedded in the signature. */
    private String url;

    /** The digest algorithm to use for the signature. */
    private String algorithm;

    /** The keystore file, the SunPKCS11 configuration file or the cloud keystore name. */
    private String keystore;

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

    public void setKeystore(String keystore) {
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
            // configure the logging
            Logger log = Logger.getLogger("net.jsign");
            log.setLevel(getLevel());
            log.setUseParentHandlers(false);
            Stream.of(log.getHandlers()).forEach(log::removeHandler);
            log.addHandler(new AntLogHandler(this));

            SignerHelper helper = new SignerHelper("attribute");
            helper.setBaseDir(getProject().getBaseDir());
            
            helper.command(command);
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
                    helper.execute(new File(fileset.getDir(), fileElement));
                }
            } else {
                helper.execute(file);
            }
        } catch (Exception e) {
            throw new BuildException(e.getMessage(), e, getLocation());
        }
    }

    /**
     * Returns the logging level equivalent to the Ant message output level.
     */
    private Level getLevel() {
        int messageOutputLevel = getMessageOutputLevel();
        switch (messageOutputLevel) {
            case MSG_ERR:
                return Level.SEVERE;
            case MSG_WARN:
                return Level.WARNING;
            case MSG_INFO:
                return Level.INFO;
            case MSG_VERBOSE:
                return Level.FINE;
            case MSG_DEBUG:
                return Level.FINEST;
            default:
                return Level.INFO;
        }
    }

    /**
     * Returns the Ant message output level.
     */
    private int getMessageOutputLevel() {
        for (Object listener : getProject().getBuildListeners()) {
            if (listener instanceof BuildLogger) {
                try {
                    Method method = BuildLogger.class.getMethod("getMessageOutputLevel"); // requires Ant 1.10.13
                    return (Integer) method.invoke(listener);
                } catch (Exception e) {
                }

                try {
                    Field field = DefaultLogger.class.getDeclaredField("msgOutputLevel");
                    field.setAccessible(true);
                    return (Integer) field.get(listener);
                } catch (Exception e) {
                }
            }
        }

        return MSG_INFO;
    }
}
