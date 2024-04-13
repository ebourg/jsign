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
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
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

    /** The operation to execute */
    @Parameter( property = "jsign.command", defaultValue = "sign" )
    private String command = "sign";

    /** The program name embedded in the signature. */
    @Parameter( property = "jsign.name" )
    private String name;

    /** The program URL embedded in the signature. */
    @Parameter( property = "jsign.url" )
    private String url;

    /** The digest algorithm to use for the signature (SHA-1, SHA-256, SHA-384 or SHA-512). */
    @Parameter( property = "jsign.algorithm", defaultValue = "SHA-256" )
    private String algorithm;

    /**
     * The keystore file, the SunPKCS11 configuration file, the cloud keystore name, or the smart card or hardware
     * token name. For file based keystores this parameter must be specified unless the keyfile and certfile parameters
     * are already specified. For smart cards and hardware tokens, this parameter may be specified to distinguish
     * between multiple connected devices.
     */
    @Parameter( property = "jsign.keystore" )
    private String keystore;

    /**
     * The password to open the keystore. The password can be loaded from a file by using the <code>file:</code> prefix
     * followed by the path of the file, from an environment variable by using the <code>env:</code> prefix followed
     * by the name of the variable, or from the Maven settings file by using the <code>mvn:</code> prefix followed by
     * the server id.
     */
    @Parameter( property = "jsign.storepass" )
    private String storepass;

    /**
     * The type of the keystore (JKS, JCEKS, PKCS12, PKCS11, ETOKEN, NITROKEY, OPENPGP, OPENSC, PIV, YUBIKEY, AWS,
     * AZUREKEYVAULT, DIGICERTONE, ESIGNER, GOOGLECLOUD, HASHICORPVAULT or ORACLECLOUD).
     */
    @Parameter( property = "jsign.storetype" )
    private String storetype;

    /**
     * The alias of the certificate used for signing in the keystore. This parameter is mandatory if the keystore
     * parameter is specified and if the keystore contains more than one alias.
     */
    @Parameter( property = "jsign.alias" )
    private String alias;

    /**
     * The file containing the PKCS#7 certificate chain (.p7b or .spc files).
     * This parameter is used in combination with the keyfile parameter.
     */
    @Parameter( property = "jsign.certfile" )
    private File certfile;

    /**
     * The file containing the private key (PEM or PVK format).
     * This parameter is used in combination with the certfile parameter.
     */
    @Parameter( property = "jsign.keyfile" )
    private File keyfile;

    /**
     * The password of the private key. When using a keystore, this parameter can be omitted if the keystore shares
     * the same password. The password can be loaded from a file by using the <code>file:</code> prefix followed by
     * the path of the file, from an environment variable by using the <code>env:</code> prefix followed by the name
     * of the variable, or from the Maven settings file by using the <code>mvn:</code> prefix followed by the server id.
     */
    @Parameter( property = "jsign.keypass" )
    private String keypass;

    /**
     * The URL of the timestamping authority.
     * Several URLs separated by a comma can be specified to fallback on alternative servers.
     */
    @Parameter( property = "jsign.tsaurl" )
    private String tsaurl;

    /** The protocol used for the timestamping (RFC3161 or Authenticode) */
    @Parameter( property = "jsign.tsmode", defaultValue = "Authenticode" )
    private String tsmode;

    /** The number of retries for timestamping */
    @Parameter( property = "jsign.tsretries", defaultValue = "3")
    private int tsretries = -1;

    /** The number of seconds to wait between timestamping retries */
    @Parameter( property = "jsign.tsretrywait", defaultValue = "10")
    private int tsretrywait = -1;

    /** Tells if previous signatures should be replaced */
    @Parameter( property = "jsign.replace", defaultValue = "false")
    private boolean replace;

    /** The encoding of the script to be signed (UTF-8 by default). */
    @Parameter( property = "jsign.encoding", defaultValue = "UTF-8")
    private String encoding = "UTF-8";

    /**
     * Tells if a detached signature should be generated or reused. The detached signature is a file in the same
     * directory using the name of the file signed with the <code>.sig</code> suffix added
     * (for example <code>application.exe.sig</code>).
     *
     * <ul>
     *   <li>If the signature doesn't exist, the file is signed as usual and the detached signature is generated.</li>
     *   <li>If the signature exists it is attached to the file, replacing any existing signature (in this case
     *       the private key isn't used for signing and no timestamping is performed)</li>
     * </ul>
     */
    @Parameter( property = "jsign.detached", defaultValue = "false")
    private boolean detached;

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    @Parameter(defaultValue = "${settings}", readonly = true)
    private Settings settings;

    @Parameter( property = "jsign.proxyId" )
    private String proxyId;

    /** Specifies whether the signing should be skipped. */
    @Parameter( property = "jsign.skip", defaultValue = "false" )
    protected boolean skip;

    @Component(hint = "mng-4384")
    private SecDispatcher securityDispatcher;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping signing");
            return;
        }

        if (file == null && fileset == null) {
            throw new MojoExecutionException("file of fileset must be set");
        }

        SignerHelper helper = new SignerHelper(new MavenConsole(getLog()), "element");
        helper.setBaseDir(project.getBasedir());
        
        helper.command(command);
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
                helper.execute(file);
            }

            if (fileset != null) {
                for (String filename : new FileSetManager().getIncludedFiles(fileset)) {
                    File file = new File(fileset.getDirectory(), filename);
                    helper.execute(file);
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

    /**
     * Decrypts a password using the Maven settings. The password specified can be either:
     * <ul>
     *   <li>unencrypted</li>
     *   <li>encrypted with the Maven master password, Base64 encoded and enclosed in curly brackets (for example <code>{COQLCE6DU6GtcS5P=}</code>)</li>
     *   <li>a reference to a server in the settings.xml file prefixed with <code>mvn:</code> (for example <code>mvn:keystore</code>)</li>
     * </ul
     *
     * @param encoded the password to be decrypted
     * @return The decrypted password
     */
    private String decrypt(String encoded) throws MojoExecutionException {
        if (encoded == null) {
            return null;
        }

        if (encoded.startsWith("mvn:")) {
            String serverId = encoded.substring(4);
            Server server = this.settings.getServer(serverId);
            if (server == null) {
                throw new MojoExecutionException("Server '" + serverId + "' not found in settings.xml");
            }
            if (server.getPassword() != null) {
                encoded = server.getPassword();
            } else if (server.getPassphrase() != null) {
                encoded = server.getPassphrase();
            } else {
                throw new MojoExecutionException("No password or passphrase found for server '" + serverId + "' in settings.xml");
            }
        }

        try {
            return securityDispatcher.decrypt(encoded);
        } catch (SecDispatcherException e) {
            getLog().error("error using security dispatcher: " + e.getMessage(), e);
            throw new MojoExecutionException("error using security dispatcher: " + e.getMessage(), e);
        }
    }
}
