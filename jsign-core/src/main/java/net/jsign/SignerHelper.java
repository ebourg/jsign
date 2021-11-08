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
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.jca.AzureKeyVaultSigningService;
import net.jsign.jca.DigiCertOneSigningService;
import net.jsign.jca.ESignerSigningService;
import net.jsign.jca.GoogleCloudSigningService;
import net.jsign.jca.SigningServiceJcaProvider;
import net.jsign.timestamp.TimestampingMode;

/**
 * Helper class to create AuthenticodeSigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task and the CLI tool.
 *
 * @since 2.0
 */
class SignerHelper {
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

    private final Console console;

    /** The name used to refer to a configuration parameter */
    private final String parameterName;

    private String keystore;
    private String storepass;
    private String storetype;
    private String alias;
    private String keypass;
    private File keyfile;
    private File certfile;
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

    private AuthenticodeSigner signer;

    public SignerHelper(Console console, String parameterName) {
        this.console = console;
        this.parameterName = parameterName;
    }

    public SignerHelper keystore(String keystore) {
        this.keystore = keystore;
        return this;
    }

    public SignerHelper keystore(File keystore) {
        this.keystore = keystore != null ? keystore.getPath() : null;
        return this;
    }

    public SignerHelper storepass(String storepass) {
        this.storepass = storepass;
        return this;
    }

    public SignerHelper storetype(String storetype) {
        this.storetype = storetype;
        return this;
    }

    public SignerHelper alias(String alias) {
        this.alias = alias;
        return this;
    }

    public SignerHelper keypass(String keypass) {
        this.keypass = keypass;
        return this;
    }

    public SignerHelper keyfile(String keyfile) {
        keyfile(createFile(keyfile));
        return this;
    }

    public SignerHelper keyfile(File keyfile) {
        this.keyfile = keyfile;
        return this;
    }

    public SignerHelper certfile(String certfile) {
        certfile(createFile(certfile));
        return this;
    }

    public SignerHelper certfile(File certfile) {
        this.certfile = certfile;
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

    public SignerHelper param(String key, String value) {
        if (value == null) {
            return this;
        }
        
        switch (key) {
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
            default:
                throw new IllegalArgumentException("Unknown " + parameterName + ": " + key);
        }
    }

    private File createFile(String file) {
        return file == null ? null : new File(file);
    }

    private AuthenticodeSigner build() throws SignerException {
        PrivateKey privateKey;
        Certificate[] chain;

        // some exciting parameter validation...
        if (keystore == null && keyfile == null && certfile == null && !"YUBIKEY".equals(storetype) && !"DIGICERTONE".equals(storetype) && !"ESIGNER".equals(storetype)) {
            throw new SignerException("keystore " + parameterName + ", or keyfile and certfile " + parameterName + "s must be set");
        }
        if (keystore != null && keyfile != null) {
            throw new SignerException("keystore " + parameterName + " can't be mixed with keyfile");
        }
        if ("AZUREKEYVAULT".equals(storetype)) {
            if (keystore == null) {
                throw new SignerException("keystore " + parameterName + " must specify the Azure vault name");
            }
            if (storepass == null) {
                throw new SignerException("storepass " + parameterName + " must specify the Azure API access token");
            }
        } else if ("DIGICERTONE".equals(storetype)) {
            if (storepass == null || storepass.split("\\|").length != 3) {
                throw new SignerException("storepass " + parameterName + " must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>");
            }
        } else if ("GOOGLECLOUD".equals(storetype)) {
            if (keystore == null) {
                throw new SignerException("keystore " + parameterName + " must specify the Goole Cloud keyring");
            }
            if (storepass == null) {
                throw new SignerException("storepass " + parameterName + " must specify the Goole Cloud API access token");
            }
            if (certfile == null) {
                throw new SignerException("certfile " + parameterName + " must be set");
            }
        } else if ("ESIGNER".equals(storetype)) {
            if (storepass == null || !storepass.contains("|")) {
                throw new SignerException("storepass " + parameterName + " must specify the SSL.com username and password: <username>|<password>");
            }
        }
        
        Provider provider = null;
        if ("PKCS11".equals(storetype)) {
            // the keystore parameter is either the provider name or the SunPKCS11 configuration file
            if (keystore != null && new File(keystore).exists()) {
                provider = ProviderUtils.createSunPKCS11Provider(keystore);
            } else if (keystore != null && keystore.startsWith("SunPKCS11-")) {
                provider = Security.getProvider(keystore);
                if (provider == null) {
                    throw new SignerException("Security provider " + keystore + " not found");
                }
            } else {
                throw new SignerException("keystore " + parameterName + " should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security");
            }
        } else if ("YUBIKEY".equals(storetype)) {
            provider = YubiKey.getProvider();
        } else if ("AZUREKEYVAULT".equals(storetype)) {
            provider = new SigningServiceJcaProvider(new AzureKeyVaultSigningService(keystore, storepass));
        } else if ("DIGICERTONE".equals(storetype)) {
            String[] elements = storepass.split("\\|");
            provider = new SigningServiceJcaProvider(new DigiCertOneSigningService(elements[0], new File(elements[1]), elements[2]));
        } else if ("GOOGLECLOUD".equals(storetype)) {
            provider = new SigningServiceJcaProvider(new GoogleCloudSigningService(keystore, storepass, alias -> {
                try {
                    return loadCertificateChain(certfile);
                } catch (IOException | CertificateException e) {
                    throw new RuntimeException("Failed to load the certificate from " + certfile, e);
                }
            }));
        } else if ("ESIGNER".equals(storetype)) {
            String[] elements = storepass.split("\\|", 2);
            String endpoint = keystore != null ? keystore : "https://cs.ssl.com";
            try {
                provider = new SigningServiceJcaProvider(new ESignerSigningService(endpoint, elements[0], elements[1]));
            } catch (IOException e) {
                throw new SignerException("Authentication failed with SSL.com", e);
            }
        }

        if (keystore != null || "YUBIKEY".equals(storetype) || "DIGICERTONE".equals(storetype)) {
            KeyStore ks;
            try {
                ks = KeyStoreUtils.load(keystore, "YUBIKEY".equals(storetype) ? "PKCS11" : storetype, storepass, provider);
            } catch (KeyStoreException e) {
                throw new SignerException("Failed to load the keystore " + keystore, e);
            }

            Set<String> aliases = null;
            if (alias == null) {
                if ("YUBIKEY".equals(storetype)) {
                    alias = "X.509 Certificate for Digital Signature";

                } else {
                    // guess the alias if there is only one in the keystore
                    try {
                        aliases = new LinkedHashSet<>(Collections.list(ks.aliases()));
                    } catch (KeyStoreException e) {
                        throw new SignerException(e.getMessage(), e);
                    }

                    if (aliases.isEmpty()) {
                        throw new SignerException("No certificate found in the keystore " + (provider != null ? provider.getName() : keystore));
                    } else if (aliases.size() == 1) {
                        alias = aliases.iterator().next();
                    } else {
                        throw new SignerException("alias " + parameterName + " must be set to select a certificate (available aliases: " + String.join(", ", aliases) + ")");
                    }
                }
            }

            try {
                chain = ks.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                throw new SignerException(e.getMessage(), e);
            }
            if (chain == null) {
                String message = "No certificate found under the alias '" + alias + "' in the keystore " + (provider != null ? provider.getName() : keystore);
                if (aliases == null) {
                    try {
                        aliases = new LinkedHashSet<>(Collections.list(ks.aliases()));
                        if (aliases.isEmpty()) {
                            message = "No certificate found in the keystore " + (provider != null ? provider.getName() : keystore);
                        } else {
                            message += " (available aliases: " + String.join(", ", aliases) + ")";
                        }
                    } catch (KeyStoreException e) {
                        message += " (couldn't load the list of available aliases: " + e.getMessage() + ")";
                    }
                }
                throw new SignerException(message);
            }
            if (certfile != null && !"GOOGLECLOUD".equals(storetype) && !"ESIGNER".equals(storetype)) {
                if (chain.length != 1) {
                    throw new SignerException("certfile " + parameterName + " can only be specified if the certificate from the keystore contains only one entry");
                }
                // replace the certificate chain from the keystore with the complete chain from file
                try {
                    Certificate[] chainFromFile = loadCertificateChain(certfile);
                    if (chainFromFile[0].equals(chain[0])) {
                        // replace certificate with complete chain
                        chain = chainFromFile;
                    } else {
                        throw new SignerException("The certificate chain in " + certfile + " does not match the chain from the keystore");
                    }
                } catch (SignerException e) {
                    throw e;
                } catch (Exception e) {
                    throw new SignerException("Failed to load the certificate from " + certfile, e);
                }
            }

            char[] password = keypass != null ? keypass.toCharArray() : null;
            if (password == null && storepass != null && !"ESIGNER".equals(storetype)) {
                // use the storepass as the keypass
                password = storepass.toCharArray();
            }

            try {
                privateKey = (PrivateKey) ks.getKey(alias, password);
            } catch (Exception e) {
                throw new SignerException("Failed to retrieve the private key from the keystore", e);
            }

        } else {
            // separate private key and certificate files (PVK/SPC)
            if (keyfile == null) {
                throw new SignerException("keyfile " + parameterName + " must be set");
            }
            if (!keyfile.exists()) {
                throw new SignerException("The keyfile " + keyfile + " couldn't be found");
            }
            if (certfile == null) {
                throw new SignerException("certfile " + parameterName + " must be set");
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
                privateKey = PrivateKeyUtils.load(keyfile, keypass != null ? keypass : storepass);
            } catch (Exception e) {
                throw new SignerException("Failed to load the private key from " + keyfile, e);
            }
        }

        if (alg != null && DigestAlgorithm.of(alg) == null) {
            throw new SignerException("The digest algorithm " + alg + " is not supported");
        }

        try {
            initializeProxy(proxyUrl, proxyUser, proxyPass);
        } catch (Exception e) {
            throw new SignerException("Couldn't initialize proxy", e);
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

    public void sign(File file) throws SignerException {
        if (file == null) {
            throw new SignerException("file must be set");
        }
        if (!file.exists()) {
            throw new SignerException("The file " + file + " couldn't be found");
        }
        
        Signable signable;
        try {
            signable = Signable.of(file, encoding);
        } catch (UnsupportedOperationException e) {
            throw new SignerException(e.getMessage());
        } catch (IOException e) {
            throw new SignerException("Couldn't open the file " + file, e);
        }

        if (detached && getDetachedSignature(file).exists()) {
            try {
                if (console != null) {
                    console.info("Attaching Authenticode signature to " + file);
                }
                attach(file);
                return;
            } catch (Exception e) {
                throw new SignerException("Couldn't attach the signature to " + file, e);
            }
        }

        try {
            if (signer == null) {
                signer = build();
            }
            
            if (console != null) {
                console.info("Adding Authenticode signature to " + file);
            }
            signer.sign(signable);

            if (detached) {
                detach(file);
            }
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        }
    }

    private void attach(File file) throws IOException, CMSException {
        File detachedSignature = getDetachedSignature(file);
        byte[] signatureBytes = FileUtils.readFileToByteArray(detachedSignature);
        CMSSignedData signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(signatureBytes).readObject()));

        Signable signable = Signable.of(file, encoding);
        signable.setSignature(signedData);
        signable.save();

        // todo warn if the hashes don't match
    }

    private void detach(File file) throws IOException {
        Signable signable = Signable.of(file, encoding);
        CMSSignedData signedData = signable.getSignatures().get(0);
        File detachedSignature = getDetachedSignature(file);
        byte[] content = signedData.toASN1Structure().getEncoded("DER");

        FileUtils.writeByteArrayToFile(detachedSignature, content);
    }

    private File getDetachedSignature(File file) {
        return new File(file.getParentFile(), file.getName() + ".sig");
    }

    /**
     * Load the certificate chain from the specified PKCS#7 files.
     */
    private Certificate[] loadCertificateChain(File file) throws IOException, CertificateException {
        try (FileInputStream in = new FileInputStream(file)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
            return certificates.toArray(new Certificate[0]);
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
                    if (console != null) {
                        console.debug("Proxy selected for " + uri + " : " + proxy);
                    }
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
