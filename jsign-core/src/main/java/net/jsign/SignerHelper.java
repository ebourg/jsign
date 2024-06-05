/**
 * Copyright 2017 Emmanuel Bourg and contributors
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
import java.io.FileWriter;
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
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.timestamp.TimestampingMode;

/**
 * Helper class to create AuthenticodeSigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task, the Maven/Gradle plugins and the CLI tool.
 *
 * @since 2.0
 */
class SignerHelper {
    public static final String PARAM_COMMAND = "command";
    public static final String PARAM_KEYSTORE = "keystore";
    public static final String PARAM_STOREPASS = "storepass";
    public static final String PARAM_STORETYPE = "storetype";
    public static final String PARAM_ALIAS = "alias";
    public static final String PARAM_KEYPASS = "keypass";
    public static final String PARAM_KEYFILE = "keyfile";
    public static final String PARAM_CERTFILE = "certfile";
    public static final String PARAM_ALG = "alg";
    public static final String PARAM_TSAURL = "tsaurl";
    public static final String PARAM_TSMODE = "tsmode";
    public static final String PARAM_TSRETRIES = "tsretries";
    public static final String PARAM_TSRETRY_WAIT = "tsretrywait";
    public static final String PARAM_NAME = "name";
    public static final String PARAM_URL = "url";
    public static final String PARAM_PROXY_URL = "proxyUrl";
    public static final String PARAM_PROXY_USER = "proxyUser";
    public static final String PARAM_PROXY_PASS = "proxyPass";
    public static final String PARAM_REPLACE = "replace";
    public static final String PARAM_ENCODING = "encoding";
    public static final String PARAM_DETACHED = "detached";
    public static final String PARAM_FORMAT = "format";

    private final Logger log = Logger.getLogger(getClass().getName());

    /** The name used to refer to a configuration parameter */
    private final String parameterName;

    private String command = "sign";
    private final KeyStoreBuilder ksparams;
    private String alias;
    private String tsaurl;
    private String tsmode;
    private int tsretries = -1;
    private int tsretrywait = -1;
    private String alg;
    private String name;
    private String url;
    private String proxyUrl;
    private String proxyUser;
    private String proxyPass;
    private boolean replace;
    private Charset encoding;
    private boolean detached;
    private String format;

    private AuthenticodeSigner signer;

    public SignerHelper(String parameterName) {
        this.parameterName = parameterName;
        this.ksparams = new KeyStoreBuilder(parameterName);
    }

    public SignerHelper command(String command) {
        this.command = command;
        return this;
    }

    public SignerHelper keystore(String keystore) {
        ksparams.keystore(keystore);
        return this;
    }

    public SignerHelper storepass(String storepass) {
        ksparams.storepass(storepass);
        return this;
    }

    public SignerHelper storetype(String storetype) {
        ksparams.storetype(storetype);
        return this;
    }

    public SignerHelper alias(String alias) {
        this.alias = alias;
        return this;
    }

    public SignerHelper keypass(String keypass) {
        ksparams.keypass(keypass);
        return this;
    }

    public SignerHelper keyfile(String keyfile) {
        ksparams.keyfile(keyfile);
        return this;
    }

    public SignerHelper keyfile(File keyfile) {
        ksparams.keyfile(keyfile);
        return this;
    }

    public SignerHelper certfile(String certfile) {
        ksparams.certfile(certfile);
        return this;
    }

    public SignerHelper certfile(File certfile) {
        ksparams.certfile(certfile);
        return this;
    }

    public SignerHelper alg(String alg) {
        this.alg = alg;
        return this;
    }

    public SignerHelper tsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
        return this;
    }

    public SignerHelper tsmode(String tsmode) {
        this.tsmode = tsmode;
        return this;
    }

    public SignerHelper tsretries(int tsretries) {
        this.tsretries = tsretries;
        return this;
    }

    public SignerHelper tsretrywait(int tsretrywait) {
        this.tsretrywait = tsretrywait;
        return this;
    }

    public SignerHelper name(String name) {
        this.name = name;
        return this;
    }

    public SignerHelper url(String url) {
        this.url = url;
        return this;
    }

    public SignerHelper proxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
        return this;
    }

    public SignerHelper proxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
        return this;
    }

    public SignerHelper proxyPass(String proxyPass) {
        this.proxyPass = proxyPass;
        return this;
    }

    public SignerHelper replace(boolean replace) {
        this.replace = replace;
        return this;
    }

    public SignerHelper encoding(String encoding) {
        this.encoding = Charset.forName(encoding);
        return this;
    }

    public SignerHelper detached(boolean detached) {
        this.detached = detached;
        return this;
    }

    public SignerHelper format(String format) {
        this.format = format;
        return this;
    }

    public SignerHelper param(String key, String value) {
        if (value == null) {
            return this;
        }
        
        switch (key) {
            case PARAM_COMMAND:    return command(value);
            case PARAM_KEYSTORE:   return keystore(value);
            case PARAM_STOREPASS:  return storepass(value);
            case PARAM_STORETYPE:  return storetype(value);
            case PARAM_ALIAS:      return alias(value);
            case PARAM_KEYPASS:    return keypass(value);
            case PARAM_KEYFILE:    return keyfile(value);
            case PARAM_CERTFILE:   return certfile(value);
            case PARAM_ALG:        return alg(value);
            case PARAM_TSAURL:     return tsaurl(value);
            case PARAM_TSMODE:     return tsmode(value);
            case PARAM_TSRETRIES:  return tsretries(Integer.parseInt(value));
            case PARAM_TSRETRY_WAIT: return tsretrywait(Integer.parseInt(value));
            case PARAM_NAME:       return name(value);
            case PARAM_URL:        return url(value);
            case PARAM_PROXY_URL:  return proxyUrl(value);
            case PARAM_PROXY_USER: return proxyUser(value);
            case PARAM_PROXY_PASS: return proxyPass(value);
            case PARAM_REPLACE:    return replace("true".equalsIgnoreCase(value));
            case PARAM_ENCODING:   return encoding(value);
            case PARAM_DETACHED:   return detached("true".equalsIgnoreCase(value));
            case PARAM_FORMAT:     return format(value);
            default:
                throw new IllegalArgumentException("Unknown " + parameterName + ": " + key);
        }
    }

    void setBaseDir(File basedir) {
        ksparams.setBaseDir(basedir);
    }

    public void execute(String file) throws SignerException {
        execute(ksparams.createFile(file));
    }

    public void execute(File file) throws SignerException {
        switch (command) {
            case "sign":
                sign(file);
                break;
            case "extract":
                extract(file);
                break;
            case "remove":
                remove(file);
                break;
            default:
                throw new SignerException("Unknown command '" + command + "'");
        }
    }

    private AuthenticodeSigner build() throws SignerException {
        KeyStore ks;
        try {
            ks = ksparams.build();
        } catch (KeyStoreException e) {
            throw new SignerException("Failed to load the keystore " + (ksparams.keystore() != null ? ksparams.keystore() : ""), e);
        }
        KeyStoreType storetype = ksparams.storetype();
        Provider provider = ksparams.provider();

        Set<String> aliases = null;
        if (alias == null) {
            // guess the alias if there is only one in the keystore
            try {
                aliases = storetype.getAliases(ks);
            } catch (KeyStoreException e) {
                throw new SignerException(e.getMessage(), e);
            }

            if (aliases.isEmpty()) {
                throw new SignerException("No certificate found in the keystore " + (provider != null ? provider.getName() : ksparams.keystore()));
            } else if (aliases.size() == 1) {
                alias = aliases.iterator().next();
            } else {
                throw new SignerException("alias " + parameterName + " must be set to select a certificate (available aliases: " + String.join(", ", aliases) + ")");
            }
        }

        Certificate[] chain;
        try {
            chain = ks.getCertificateChain(alias);
        } catch (KeyStoreException e) {
            throw new SignerException(e.getMessage(), e);
        }
        if (chain == null) {
            String message = "No certificate found under the alias '" + alias + "' in the keystore " + (provider != null ? provider.getName() : ksparams.keystore());
            if (aliases == null) {
                try {
                    aliases = new LinkedHashSet<>(Collections.list(ks.aliases()));
                    if (aliases.isEmpty()) {
                        message = "No certificate found in the keystore " + (provider != null ? provider.getName() : ksparams.keystore());
                    } else if (aliases.contains(alias)) {
                        message = "The keystore password must be specified";
                    } else {
                        message += " (available aliases: " + String.join(", ", aliases) + ")";
                    }
                } catch (KeyStoreException e) {
                    message += " (couldn't load the list of available aliases: " + e.getMessage() + ")";
                }
            }
            throw new SignerException(message);
        }
        if (ksparams.certfile() != null && storetype.hasCertificate()) {
            if (chain.length != 1) {
                throw new SignerException("certfile " + parameterName + " can only be specified if the certificate from the keystore contains only one entry");
            }
            // replace the certificate chain from the keystore with the complete chain from file
            try {
                Certificate[] chainFromFile = CertificateUtils.loadCertificateChain(ksparams.certfile());
                if (chainFromFile[0].equals(chain[0])) {
                    // replace certificate with complete chain
                    chain = chainFromFile;
                } else {
                    throw new SignerException("The certificate chain in " + ksparams.certfile() + " does not match the chain from the keystore");
                }
            } catch (SignerException e) {
                throw e;
            } catch (Exception e) {
                throw new SignerException("Failed to load the certificate from " + ksparams.certfile(), e);
            }
        }

        String storepass = ksparams.storepass();
        String keypass = ksparams.keypass();
        char[] password = keypass != null ? keypass.toCharArray() : null;
        if (password == null && storepass != null && storetype.reuseKeyStorePassword()) {
            // use the storepass as the keypass
            password = storepass.toCharArray();
        }

        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) ks.getKey(alias, password);
        } catch (Exception e) {
            throw new SignerException("Failed to retrieve the private key from the keystore", e);
        }

        if (alg != null && DigestAlgorithm.of(alg) == null) {
            throw new SignerException("The digest algorithm " + alg + " is not supported");
        }

        try {
            initializeProxy(proxyUrl, proxyUser, proxyPass);
        } catch (Exception e) {
            throw new SignerException("Couldn't initialize proxy", e);
        }

        // enable timestamping with Azure Trusted Signing
        if (tsaurl == null && storetype == KeyStoreType.TRUSTEDSIGNING) {
            tsaurl = "http://timestamp.acs.microsoft.com/";
            tsmode = TimestampingMode.RFC3161.name();
            tsretries = 3;
        }
        
        // configure the signer
        return new AuthenticodeSigner(chain, privateKey)
                .withProgramName(name)
                .withProgramURL(url)
                .withDigestAlgorithm(DigestAlgorithm.of(alg))
                .withSignatureProvider(provider)
                .withSignaturesReplaced(replace)
                .withTimestamping(tsaurl != null || tsmode != null)
                .withTimestampingMode(tsmode != null ? TimestampingMode.of(tsmode) : TimestampingMode.AUTHENTICODE)
                .withTimestampingRetries(tsretries)
                .withTimestampingRetryWait(tsretrywait)
                .withTimestampingAuthority(tsaurl != null ? tsaurl.split(",") : null);
    }

    public void sign(String file) throws SignerException {
        sign(ksparams.createFile(file));
    }

    public void sign(File file) throws SignerException {
        if (file == null) {
            throw new SignerException("file must be set");
        }
        if (!file.exists()) {
            throw new SignerException("The file " + file + " couldn't be found");
        }
        
        try (Signable signable = Signable.of(file, encoding)) {
            File detachedSignature = getDetachedSignature(file);
            if (detached && detachedSignature.exists()) {
                try {
                    log.info("Attaching Authenticode signature to " + file);
                    attach(signable, detachedSignature);
                } catch (Exception e) {
                    throw new SignerException("Couldn't attach the signature to " + file, e);
                }

            } else {
                if (signer == null) {
                    signer = build();
                }

                log.info("Adding Authenticode signature to " + file);
                signer.sign(signable);

                if (detached) {
                    detach(signable, detachedSignature);
                }
            }

        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new SignerException(e.getMessage());
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        }
    }

    private void attach(Signable signable, File detachedSignature) throws IOException, CMSException {
        byte[] signatureBytes = Files.readAllBytes(detachedSignature.toPath());
        CMSSignedData signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(signatureBytes).readObject()));

        signable.setSignature(signedData);
        signable.save();
        // todo warn if the hashes don't match
    }

    private void detach(Signable signable, File detachedSignature) throws IOException {
        CMSSignedData signedData = signable.getSignatures().get(0);
        byte[] content = signedData.toASN1Structure().getEncoded("DER");
        if (format == null || "DER".equalsIgnoreCase(format)) {
            Files.write(detachedSignature.toPath(), content);
        } else if ("PEM".equalsIgnoreCase(format)) {
            try (FileWriter out = new FileWriter(detachedSignature)) {
                String encoded = Base64.getEncoder().encodeToString(content);
                out.write("-----BEGIN PKCS7-----\n");
                for (int i = 0; i < encoded.length(); i += 64) {
                    out.write(encoded.substring(i, Math.min(i + 64, encoded.length())));
                    out.write('\n');
                }
                out.write("-----END PKCS7-----\n");
            }
        } else {
            throw new IllegalArgumentException("Unknown output format '" + format + "'");
        }
    }

    private File getDetachedSignature(File file) {
        return new File(file.getParentFile(), file.getName() + ".sig");
    }

    private void extract(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        try (Signable signable = Signable.of(file)) {
            List<CMSSignedData> signatures = signable.getSignatures();
            if (signatures.isEmpty()) {
                throw new SignerException("No signature found in " + file);
            }

            File detachedSignature = getDetachedSignature(file);
            if ("PEM".equalsIgnoreCase(format)) {
                detachedSignature = new File(detachedSignature.getParentFile(), detachedSignature.getName() + ".pem");
            }
            log.info("Extracting signature to " + detachedSignature);
            detach(signable, detachedSignature);
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new SignerException(e.getMessage());
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't extract the signature from " + file, e);
        }
    }

    private void remove(File file) throws SignerException {
        if (!file.exists()) {
            throw new SignerException("Couldn't find " + file);
        }

        try (Signable signable = Signable.of(file)) {
            List<CMSSignedData> signatures = signable.getSignatures();
            if (signatures.isEmpty()) {
                log.severe("No signature found in " + file);
                return;
            }

            log.info("Removing signature from " + file);
            signable.setSignature(null);
            signable.save();
        } catch (UnsupportedOperationException | IllegalArgumentException e) {
            throw new SignerException(e.getMessage());
        } catch (Exception e) {
            throw new SignerException("Couldn't remove the signature from " + file, e);
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
                public List<Proxy> select(URI uri) {
                    Proxy proxy;
                    if (uri.getScheme().equals("socket")) {
                        proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(url.getHost(), port));
                    } else {
                        proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(url.getHost(), port));
                    }
                    log.fine("Proxy selected for " + uri + " : " + proxy);
                    return Collections.singletonList(proxy);
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
