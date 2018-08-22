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
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
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
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import sun.security.pkcs11.SunPKCS11;

import net.jsign.pe.PEFile;
import net.jsign.timestamp.TimestampingMode;

/**
 * Helper class to create PESigner instances with untyped parameters.
 * This is used internally to share the parameter validation logic
 * between the Ant task and the CLI tool.
 *
 * @since 2.0
 */
class PESignerHelper {
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

    private Console console;

    /** The name used to refer to a configuration parameter */
    private String parameterName = "parameter";

    private File keystore;
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

    public PESignerHelper(Console console, String parameterName) {
        this.console = console;
        this.parameterName = parameterName;
    }

    public PESignerHelper keystore(String keystore) {
        keystore(createFile(keystore));
        return this;
    }

    public PESignerHelper keystore(File keystore) {
        this.keystore = keystore;
        return this;
    }

    public PESignerHelper storepass(String storepass) {
        this.storepass = storepass;
        return this;
    }

    public PESignerHelper storetype(String storetype) {
        this.storetype = storetype;
        return this;
    }

    public PESignerHelper alias(String alias) {
        this.alias = alias;
        return this;
    }

    public PESignerHelper keypass(String keypass) {
        this.keypass = keypass;
        return this;
    }

    public PESignerHelper keyfile(String keyfile) {
        keyfile(createFile(keyfile));
        return this;
    }

    public PESignerHelper keyfile(File keyfile) {
        this.keyfile = keyfile;
        return this;
    }

    public PESignerHelper certfile(String certfile) {
        certfile(createFile(certfile));
        return this;
    }

    public PESignerHelper certfile(File certfile) {
        this.certfile = certfile;
        return this;
    }

    public PESignerHelper alg(String alg) {
        this.alg = alg;
        return this;
    }

    public PESignerHelper tsaurl(String tsaurl) {
        this.tsaurl = tsaurl;
        return this;
    }

    public PESignerHelper tsmode(String tsmode) {
        this.tsmode = tsmode;
        return this;
    }

    public PESignerHelper tsretries(int tsretries) {
        this.tsretries = tsretries;
        return this;
    }

    public PESignerHelper tsretrywait(int tsretrywait) {
        this.tsretrywait = tsretrywait;
        return this;
    }

    public PESignerHelper name(String name) {
        this.name = name;
        return this;
    }

    public PESignerHelper url(String url) {
        this.url = url;
        return this;
    }

    public PESignerHelper proxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
        return this;
    }

    public PESignerHelper proxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
        return this;
    }

    public PESignerHelper proxyPass(String proxyPass) {
        this.proxyPass = proxyPass;
        return this;
    }

    public PESignerHelper replace(boolean replace) {
        this.replace = replace;
        return this;
    }

    public PESignerHelper param(String key, String value) {
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
            default:
                throw new IllegalArgumentException("Unknown " + parameterName + ": " + key);
        }
    }

    private File createFile(String file) {
        return file == null ? null : new File(file);
    }

    public PESigner build() throws SignerException {
        PrivateKey privateKey;
        Certificate[] chain;

        // some exciting parameter validation...
        if (keystore == null && keyfile == null && certfile == null) {
            throw new SignerException("keystore " + parameterName + ", or keyfile and certfile " + parameterName + "s must be set");
        }
        if (keystore != null && keyfile != null) {
            throw new SignerException("keystore " + parameterName + " can't be mixed with keyfile");
        }

        Provider provider = null;
        if ("PKCS11".equals(storetype)) {
            // the keystore parameter is either the provider name or the SunPKCS11 configuration file
            if (keystore != null && keystore.exists()) {
                provider = createSunPKCS11Provider(keystore);
            } else if (keystore != null && keystore.getName().startsWith("SunPKCS11-")) {
                provider = Security.getProvider(keystore.getName());
                if (provider == null) {
                    throw new SignerException("Security provider " + keystore.getName() + " not found");
                }
            } else {
                throw new SignerException("keystore " + parameterName + " should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security");
            }
        }

        if (keystore != null) {
            KeyStore ks;
            try {
                ks = KeyStoreUtils.load(keystore, storetype, storepass, provider);
            } catch (KeyStoreException e) {
                throw new SignerException(e.getMessage(), e);
            }

            if (alias == null) {
                throw new SignerException("alias " + parameterName + " must be set");
            }

            try {
                chain = ks.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                throw new SignerException(e.getMessage(), e);
            }
            if (chain == null) {
                throw new SignerException("No certificate found under the alias '" + alias + "' in the keystore " + (provider != null ? provider.getName() : keystore));
            }
			if (certfile != null) {
				if (chain.length != 1) {
					throw new SignerException("Certificate chain from file can only be specified if certificate from keystore contains only 1 entry");
				}
				// replace certificate chain with complete chain from file
				try {
					Certificate[] chainFromFile = loadCertificateChain(certfile);
					if (chainFromFile[0].equals(chain[0])) {
						// replace certificate with complete chain
						chain = chainFromFile;
					} else {
						throw new SignerException("Certificate chain in file does not match chain from keystore");
					}
				} catch (SignerException e) {
					throw e;
				} catch (Exception e) {
					throw new SignerException("Failed to load the certificate from " + certfile, e);
				}
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
            throw new SignerException("Couldn't initialize proxy ", e);
        }

        // and now the actual work!
        return new PESigner(chain, privateKey)
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

    /**
     * Create a SunPKCS11 provider with the specified configuration file.
     *
     * @param configuration the SunPKCS11 configuration file
     */
    private Provider createSunPKCS11Provider(File configuration) throws SignerException {
        try {
            try {
                // Java 9 and later, using the Provider.configure() method
                Method providerConfigureMethod = Provider.class.getMethod("configure", String.class);
                Provider provider = Security.getProvider("SunPKCS11");
                return (Provider) providerConfigureMethod.invoke(provider, keystore.getPath());
            } catch (NoSuchMethodException e) {
                // prior to Java 9, direct instantiation of the SunPKCS11 class
                Constructor<SunPKCS11> sunpkcs11Constructor = SunPKCS11.class.getConstructor(String.class);
                return sunpkcs11Constructor.newInstance(keystore.getPath());
            }
        } catch (Exception e) {
            throw new SignerException("Failed to create a SunPKCS11 provider from the configuration file " + configuration, e);
        }
    }

    public void sign(File file) throws SignerException {
        PESigner signer;
        try {
            signer = build();
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        }

        if (file == null) {
            throw new SignerException("file must be set");
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

        try {
            if (console != null) {
                console.info("Adding Authenticode signature to " + file);
            }
            signer.sign(peFile);
        } catch (Exception e) {
            throw new SignerException("Couldn't sign " + file, e);
        } finally {
            try {
                peFile.close();
            } catch (IOException e) {
                if (console != null) {
                    console.warn("Couldn't close " + file, e);
                }
            }
        }
    }

    /**
     * Load the certificate chain from the specified PKCS#7 files.
     */
    @SuppressWarnings("unchecked")
    private Certificate[] loadCertificateChain(File file) throws IOException, CertificateException {
        try (FileInputStream in = new FileInputStream(file)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Collection<Certificate> certificates = (Collection<Certificate>) certificateFactory.generateCertificates(in);
            return certificates.toArray(new Certificate[certificates.size()]);
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
