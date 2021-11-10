/**
 * Copyright 2017 Emmanuel Bourg
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

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Settings;
import org.apache.maven.shared.model.fileset.FileSet;
import org.apache.maven.shared.model.fileset.util.FileSetManager;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

/**
 * Maven plugin for signing files with Authenticode.
 * 
 * @author Emmanuel Bourg
 * @since 2.0
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.PACKAGE)
public class JsignMojo extends AbstractMojo {

    /** The file to be signed. Use {@link #fileset} to sign multiple files using the same certificate. */
    @Parameter
    private File file;

    /** The set of files to be signed. */
    @Parameter
    private FileSet fileset;

    /** The program name embedded in the signature. */
    @Parameter( property = "jsign.name" )
    private String name;

    /** The program URL embedded in the signature. */
    @Parameter( property = "jsign.url" )
    private String url;

    /** The digest algorithm to use for the signature (SHA-1, SHA-256, SHA-384 or SHA-512). */
    @Parameter( property = "jsign.algorithm", defaultValue = "SHA-256" )
    private String algorithm;

    /** The keystore file. Required, unless certfile and keyfile are specified. */
    @Parameter( property = "jsign.keystore" )
    private File keystore;

    /** The password for the keystore. */
    @Parameter( property = "jsign.storepass" )
    private String storepass;

    /** The type of the keystore (JKS, PKCS12, PKCS11, YUBIKEY, AZUREKEYVAULT, DIGICERTONE, ESIGNER or GOOGLECLOUD). */
    @Parameter( property = "jsign.storetype" )
    private String storetype;

    /** The alias of the certificate in the keystore. Required if a keystore is specified. */
    @Parameter( property = "jsign.alias" )
    private String alias;

    /** The file containing the PKCS#7 certificate chain (.p7b or .spc files). */
    @Parameter( property = "jsign.certfile" )
    private File certfile;

    /** The file containing the private key (PEM or PVK format) */
    @Parameter( property = "jsign.keyfile" )
    private File keyfile;

    /** The password for the key in the store (if different from the keystore password) or in the keyfile. */
    @Parameter( property = "jsign.keypass" )
    private String keypass;

    /** The URL of the timestamping authority. */
    @Parameter( property = "jsign.tsaurl" )
    private String tsaurl;

    /** The protocol used for the timestamping (RFC3161 or Authenticode) */
    @Parameter( property = "jsign.tsmode" )
    private String tsmode;

    /** The number of retries for timestamping */
    @Parameter( property = "jsign.tsretries" )
    private int tsretries = -1;

    /** The number of seconds to wait between timestamping retries */
    @Parameter( property = "jsign.tsretrywait" )
    private int tsretrywait = -1;

    /** Tells if previous signatures should be replaced */
    @Parameter( property = "jsign.replace", defaultValue = "false")
    private boolean replace;

    /** The encoding of the script to be signed (UTF-8 by default). */
    @Parameter( property = "jsign.encoding", defaultValue = "UTF-8")
    private String encoding = "UTF-8";

    /** Tells if a detached signature should be generated or reused. */
    @Parameter( property = "jsign.detached", defaultValue = "false")
    private boolean detached;

    @Parameter(defaultValue = "${settings}", readonly = true)
    private Settings settings;

    @Parameter( property = "jsign.proxyId" )
    private String proxyId;

    @Component(hint = "mng-4384")
    private SecDispatcher securityDispatcher;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (file == null && fileset == null) {
            throw new MojoExecutionException("file of fileset must be set");
        }

        SignerHelper helper = new SignerHelper(new MavenConsole(getLog()), "element");
        
        helper.name(name);
        helper.url(url);
        helper.alg(algorithm);
        helper.keystore(keystore);
        helper.storepass(decrypt(storepass));
        helper.storetype(storetype);
        helper.alias(alias);
        helper.certfile(certfile);
        helper.keyfile(keyfile);
        helper.keypass(decrypt(keypass));
        helper.tsaurl(tsaurl);
        helper.tsmode(tsmode);
        helper.tsretries(tsretries);
        helper.tsretrywait(tsretrywait);
        helper.replace(replace);
        helper.encoding(encoding);
        helper.detached(detached);

        Proxy proxy = getProxyFromSettings();
        if (proxy != null) {
            helper.proxyUrl(proxy.getProtocol() + "://" + proxy.getHost() + ":" + proxy.getPort());
            helper.proxyUser(proxy.getUsername());
            helper.proxyPass(proxy.getPassword());
        }

        try {
            if (file != null) {
                helper.sign(file);
            }

            if (fileset != null) {
                for (String filename : new FileSetManager().getIncludedFiles(fileset)) {
                    File file = new File(fileset.getDirectory(), filename);
                    helper.sign(file);
                }
            }
        } catch (SignerException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

    private Proxy getProxyFromSettings() throws MojoExecutionException {
        if (settings == null) {
            return null;
        }

        if (proxyId != null) {
            for (Proxy proxy : settings.getProxies()) {
                if (proxyId.equals(proxy.getId())) {
                    return proxy;
                }
            }
            throw new MojoExecutionException("Configured proxy with id=" + proxyId + " not found");
        }

        // Get active http/https proxy
        for (Proxy proxy : settings.getProxies()) {
            if (proxy.isActive() && ("http".equalsIgnoreCase(proxy.getProtocol()) || "https".equalsIgnoreCase(proxy.getProtocol()))) {
                return proxy;
            }
        }

        return null;
    }

    private String decrypt(String encoded) throws MojoExecutionException {
        if (encoded == null) {
            return null;
        }

        try {
            return securityDispatcher.decrypt(encoded);
        } catch (SecDispatcherException e) {
            getLog().error("error using security dispatcher: " + e.getMessage(), e);
            throw new MojoExecutionException("error using security dispatcher: " + e.getMessage(), e);
        }
    }
}
