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
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import net.jsign.pe.PEFile;
import net.jsign.timestamp.TimestampingMode;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Command line interface for signing PE files.
 *
 * @author Emmanuel Bourg
 * @since 1.1
 */
public class PESignerCLI {

    public static void main(String... args) {
        try {
            new PESignerCLI().execute(args);
        } catch (SignerException e) {
            System.err.println("pesign: " + e.getMessage());
            if (e.getCause() != null) {
                e.getCause().printStackTrace(System.err);
            }
            System.err.println("Try `pesign --help' for more information.");
            System.exit(1);
        }
    }

    private Options options;

    PESignerCLI() {
        options = new Options();
        options.addOption(OptionBuilder.hasArg().withLongOpt("keystore").withArgName("FILE").withDescription("The keystore file").withType(File.class).create('s'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("storepass").withArgName("PASSWORD").withDescription("The password to open the keystore").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("storetype").withArgName("TYPE").withDescription("The type of the keystore:\n- JKS: Java keystore (.jks files)\n- PKCS12: Standard PKCS#12 keystore (.p12 or .pfx files)\n").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("alias").withArgName("NAME").withDescription("The alias of the certificate used for signing in the keystore.").create('a'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("keypass").withArgName("PASSWORD").withDescription("The password of the private key. When using a keystore, this parameter can be omitted if the keystore shares the same password.").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("keyfile").withArgName("FILE").withDescription("The file containing the private key. Only PVK files are supported. ").withType(File.class).create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("certfile").withArgName("FILE").withDescription("The file containing the PKCS#7 certificate chain\n(.p7b or .spc files).").withType(File.class).create('c'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("keyfile").withArgName("FILE").withDescription("The file containing the private key. Only PVK files are supported. ").withType(File.class).create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("alg").withArgName("ALGORITHM").withDescription("The digest algorithm (SHA-1, SHA-256, SHA-384 or SHA-512)").create('d'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("tsaurl").withArgName("URL").withDescription("The URL of the timestamping authority.").create('t'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("tsmode").withArgName("MODE").withDescription("The timestamping mode (RFC3161 or Authenticode)").create('m'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("name").withArgName("NAME").withDescription("The name of the application").create('n'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("url").withArgName("URL").withDescription("The URL of the application").create('u'));
        options.addOption(OptionBuilder.hasArg().withLongOpt("proxyUrl").withArgName("URL").withDescription("The URL of the HTTP proxy").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("proxyUser").withArgName("NAME").withDescription("The user for the HTTP proxy. If an user is needed.").create());
        options.addOption(OptionBuilder.hasArg().withLongOpt("proxyPass").withArgName("PASSWORD").withDescription("The password for the HTTP proxy user. If an user is needed.").create());
        options.addOption(OptionBuilder.withLongOpt("help").withDescription("Print the help").create('h'));
    }

    void execute(String... args) throws SignerException {
        DefaultParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("help") || args.length == 0) {
                printHelp();
                return;
            }

            File keystore = cmd.hasOption("keystore") ? new File(cmd.getOptionValue("keystore")) : null;
            String storepass = cmd.getOptionValue("storepass");
            String storetype = cmd.getOptionValue("storetype");
            String alias = cmd.getOptionValue("alias");
            String keypass = cmd.getOptionValue("keypass");
            File keyfile = cmd.hasOption("keyfile") ? new File(cmd.getOptionValue("keyfile")) : null;
            File certfile = cmd.hasOption("certfile") ? new File(cmd.getOptionValue("certfile")) : null;
            String tsaurl = cmd.getOptionValue("tsaurl");
            String tsmode = cmd.getOptionValue("tsmode");
            String algorithm = cmd.getOptionValue("alg");
            String name = cmd.getOptionValue("name");
            String url = cmd.getOptionValue("url");
            
            String proxyUrl = cmd.getOptionValue("proxyUrl");
            String proxyUser = cmd.getOptionValue("proxyUser");
            String proxyPassword = cmd.getOptionValue("proxyPass");
            
            File file = cmd.getArgList().isEmpty() ? null : new File(cmd.getArgList().get(0));

            if (keystore != null && storetype == null) {
                // guess the type of the keystore from the extension of the file
                String filename = keystore.getName().toLowerCase();
                if (filename.endsWith(".p12") || filename.endsWith(".pfx")) {
                    storetype = "PKCS12";
                } else {
                    storetype = "JKS";
                }
            }

            
            PrivateKey privateKey;
            Certificate[] chain;

            // some exciting parameter validation...
            if (keystore == null && keyfile == null && certfile == null) {
                throw new SignerException("keystore option, or keyfile and certfile options must be set");
            }
            if (keystore != null && (keyfile != null || certfile != null)) {
                throw new SignerException("keystore option can't be mixed with keyfile or certfile");
            }

            if (keystore != null) {
                // JKS or PKCS12 keystore 
                KeyStore ks;
                try {
                    ks = KeyStore.getInstance(storetype);
                } catch (KeyStoreException e) {
                    throw new SignerException("keystore type '" + storetype + "' is not supported", e);
                }

                if (!keystore.exists()) {
                    throw new SignerException("The keystore " + keystore + " couldn't be found");
                }
                FileInputStream in = null;
                try {
                    in = new FileInputStream(keystore);
                    ks.load(in, storepass != null ? storepass.toCharArray() : null);
                } catch (Exception e) {
                    throw new SignerException("Unable to load the keystore " + keystore, e);
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
                    throw new SignerException("alias option must be set");
                }

                try {
                    chain = ks.getCertificateChain(alias);
                } catch (KeyStoreException e) {
                    throw new SignerException(e.getMessage(), e);
                }
                if (chain == null) {
                    throw new SignerException("No certificate found under the alias '" + alias + "' in the keystore " + keystore);
                }

                char[] password = keypass != null ? keypass.toCharArray() : storepass.toCharArray();

                try {
                    privateKey = (PrivateKey) ks.getKey(alias, password);
                } catch (Exception e) {
                    throw new SignerException("Failed to retrieve the private key from the keystore", e);
                }

            } else {
                // separate private key and certificate files (PVK/SPC)
                if (keyfile == null) {
                    throw new SignerException("keyfile option must be set");
                }
                if (!keyfile.exists()) {
                    throw new SignerException("The keyfile " + keyfile + " couldn't be found");
                }
                if (certfile == null) {
                    throw new SignerException("certfile option must be set");
                }
                if (!certfile.exists()) {
                    throw new SignerException("The certfile " + certfile + " couldn't be found");
                }

                // load the certificate chain
                try {
                    chain = loadCertificateChain(certfile);
                } catch (Exception e) {
                    throw new SignerException("Failed to load the certificate from " + certfile, e);
                }

                // load the private key
                try {
                    privateKey = PVK.parse(keyfile, keypass);
                } catch (Exception e) {
                    throw new SignerException("Failed to load the private key from " + keyfile, e);
                }
            }

            if (algorithm != null && DigestAlgorithm.of(algorithm) == null) {
                throw new SignerException("The digest algorithm " + algorithm + " is not supported");
            }
            
            if (file == null) {
                throw new SignerException("missing file argument");
            }
            if (!file.exists()) {
                throw new SignerException("The file " + file + " couldn't be found");
            }

            PEFile peFile;
            try {
                peFile = new PEFile(file);
            } catch (IOException e) {
                throw new SignerException("Couldn't open the executable file " + file, e);
            }

            // and now the actual work!
            PESigner signer = new PESigner(chain, privateKey)
                    .withProgramName(name)
                    .withProgramURL(url)
                    .withDigestAlgorithm(DigestAlgorithm.of(algorithm))
                    .withTimestamping(tsaurl != null || tsmode != null)
                    .withTimestampingMode(tsmode != null ? TimestampingMode.of(tsmode) : TimestampingMode.AUTHENTICODE)
                    .withTimestampingAutority(tsaurl);


            try {
                initializeProxy(proxyUrl, proxyUser, proxyPassword);
                System.out.println("Adding Authenticode signature to " + file);
                signer.sign(peFile);
            } catch (Exception e) {
                throw new SignerException("Couldn't sign " + file, e);
            } finally {
                try {
                    peFile.close();
                } catch (IOException e) {
                    System.err.println("Couldn't close " + file);
                    e.printStackTrace(System.err);
                }
            }


        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    private void printHelp() {
        String header = "Sign and timestamp a Windows executable file.\n\n";
        String footer = "\nPlease report suggestions and issues on the GitHub project at https://github.com/ebourg/jsign/issues";

        HelpFormatter formatter = new HelpFormatter();
        formatter.setOptionComparator(null);
        formatter.setWidth(85);
        formatter.setDescPadding(1);
        formatter.printHelp("java -jar jsign.jar [OPTIONS] FILE", header, options, footer);
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
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Initializes the proxy.
     * 
     * @param proxyUrl       the url of the proxy (either as hostname:port or http[s]://hostname:port)
     * @param proxyUser      the username for the proxy authentication
     * @param proxyPassword  the password for the proxy authentication
     */
    private void initializeProxy(String proxyUrl, final String proxyUser, final String proxyPassword) throws MalformedURLException {
   		// Do nothing if there is no proxy url.
   		if (proxyUrl != null && proxyUrl.trim().length() > 0) {
            if (!proxyUrl.trim().startsWith("http")) {
                proxyUrl = "http://" + proxyUrl.trim();
            }
   			final URL url = new URL(proxyUrl);
   			final int port = url.getPort() < 0 ? 80 : url.getPort();
   
   			ProxySelector.setDefault(new ProxySelector() {
                private List<Proxy> proxies = Collections.singletonList(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(url.getHost(), port)));
                
                public List<Proxy> select(URI uri) {
                    return proxies;
                }

                public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
                }
            });

            if (proxyUser != null && proxyUser.length() > 0 && proxyPassword != null) {
                Authenticator.setDefault(new Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(proxyUser, proxyPassword.toCharArray());
                    }
                });
            }
   		}
   	}
}
