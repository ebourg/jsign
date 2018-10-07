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
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Maven plugin for signing PE files.
 * 
 * @author Emmanuel Bourg
 * @since 2.0
 */
@Mojo(name = "sign")
public class PESignerMojo extends AbstractMojo {

    /** The file to be signed. */
    @Parameter(required = true)
    private File file;

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

    /** The type of the keystore (JKS or PKCS12). */
    @Parameter( property = "jsign.storetype", defaultValue = "JKS" )
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
    @Parameter( property = "jsign.tsmode", defaultValue = "authenticode" )
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

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        PESignerHelper helper = new PESignerHelper(new MavenConsole(getLog()), "element");
        
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
        
        try {
            helper.sign(file);
        } catch (SignerException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }
}
