/**
 * Copyright 2016
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
import java.util.Map;

import net.jsign.log.PELog;
import net.jsign.timestamp.TimestampingMode;

/**
 * Builder to help create PESigner instance.
 *
 * @since 1.4
 */
public class PESignerBuilder {
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
    public static final String PARAM_NAME = "name";
    public static final String PARAM_URL = "url";
    public static final String PARAM_PROXY_URL = "proxyUrl";
    public static final String PARAM_PROXY_USER = "proxyUser";
    public static final String PARAM_PROXY_PASS = "proxyPass";

    private PELog log;

    private File keystore;
    private String storepass;
    private String storetype;
    private String alias;
    private String keypass;
    private File keyfile;
    private File certfile;
    private String tsaurl;
    private String tsmode;
    private String alg;
    private String name;
    private String url;
    private String proxyUrl;
    private String proxyUser;
    private String proxyPass;

    public PESignerBuilder(PELog log) {
        this.log = log;
    }

    public PESignerBuilder keystore(String keystore) {
        keystore(createFile(keystore));
        return this;
    }

    public PESignerBuilder keystore(File keystore) {
        this.keystore = keystore;
        return this;
    }

    public PESignerBuilder storepass(String storepass) {
        this.storepass = storepass;
        return this;
    }

    public PESignerBuilder storetype(String storetype) {
        this.storetype = storetype;
        return this;
    }

    public PESignerBuilder alias(String alias) {
        this.alias = alias;
        return this;
    }

    public PESignerBuilder keypass(String keypass) {
        this.keypass = keypass;
        return this;
    }

    public PESignerBuilder keyfile(String keyfile) {
        keyfile(createFile(keyfile));
        return this;
    }

    public PESignerBuilder keyfile(File keyfile) {
        this.keyfile = keyfile;
        return this;
    }

    public PESignerBuilder certfile(String certfile) {
        certfile(createFile(certfile));
        return this;
    }

    public PESignerBuilder certfile(File certfile) {
        this.certfile = certfile;
        return this;
    }

    public PESignerBuilder alg(String alg) {
        this.alg = alg;
        return this;
    }

    public PESignerBuilder tsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
        return this;
    }

    public PESignerBuilder tsmode(String tsmode) {
        this.tsmode = tsmode;
        return this;
    }

    public PESignerBuilder name(String name) {
        this.name = name;
        return this;
    }

    public PESignerBuilder url(String url) {
        this.url = url;
        return this;
    }

    public PESignerBuilder proxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
        return this;
    }

    public PESignerBuilder proxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
        return this;
    }

    public PESignerBuilder proxyPass(String proxyPass) {
        this.proxyPass = proxyPass;
        return this;
    }

    public PESignerBuilder map(Map<?, ?> map) {
        for (Object key : map.entrySet()) {
            String keyStr = String.valueOf(key);
            Object value = map.get(key);

            if (value != null) {
                param(keyStr, String.valueOf(value));
            }
        }

        return this;
    }

    public PESignerBuilder param(String key, String value) {
        if (PARAM_KEYSTORE.equals(key)) {
            keystore(value);
        } else if (PARAM_STOREPASS.equals(key)) {
            storepass(value);
        } else if (PARAM_STORETYPE.equals(key)) {
            storetype(value);
        } else if (PARAM_ALIAS.equals(key)) {
            alias(value);
        } else if (PARAM_KEYPASS.equals(key)) {
            keypass(value);
        } else if (PARAM_KEYFILE.equals(key)) {
            keyfile(value);
        } else if (PARAM_CERTFILE.equals(key)) {
            certfile(value);
        } else if (PARAM_ALG.equals(key)) {
            alg(value);
        } else if (PARAM_TSAURL.equals(key)) {
            tsaurl(value);
        } else if (PARAM_TSMODE.equals(key)) {
            tsmode(value);
        } else if (PARAM_NAME.equals(key)) {
            name(value);
        } else if (PARAM_URL.equals(key)) {
            url(value);
        } else if (PARAM_PROXY_URL.equals(key)) {
            proxyUrl(value);
        } else if (PARAM_PROXY_USER.equals(key)) {
            proxyUser(value);
        } else if (PARAM_PROXY_PASS.equals(key)) {
            proxyPass(value);
        } else {
            throw new IllegalArgumentException("unknown param: " + key);
        }

        return this;
    }

    private File createFile(String file) {
        return file == null ? null : new File(file);
    }

    public PESigner build() throws SignerException {
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

        if (alg != null && DigestAlgorithm.of(alg) == null) {
            throw new SignerException("The digest algorithm " + alg + " is not supported");
        }

        try {
            initializeProxy(proxyUrl, proxyUser, proxyPass);
        } catch (Exception e) {
            throw new SignerException("Couldn't initialize proxy ", e);
        }

        // and now the actual work!
        PESigner signer = new PESigner(chain, privateKey)
                .withLog(log)
                .withProgramName(name)
                .withProgramURL(url)
                .withDigestAlgorithm(DigestAlgorithm.of(alg))
                .withTimestamping(tsaurl != null || tsmode != null)
                .withTimestampingMode(tsmode != null ? TimestampingMode.of(tsmode) : TimestampingMode.AUTHENTICODE)
                .withTimestampingAutority(tsaurl);

        return signer;
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
