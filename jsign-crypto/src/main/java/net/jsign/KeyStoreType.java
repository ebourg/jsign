/**
 * Copyright 2023 Emmanuel Bourg
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
import java.net.UnknownServiceException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Function;
import javax.smartcardio.CardException;

import net.jsign.jca.AmazonCredentials;
import net.jsign.jca.AmazonSigningService;
import net.jsign.jca.AzureKeyVaultSigningService;
import net.jsign.jca.AzureTrustedSigningService;
import net.jsign.jca.DigiCertOneSigningService;
import net.jsign.jca.ESignerSigningService;
import net.jsign.jca.GaraSignCredentials;
import net.jsign.jca.GaraSignSigningService;
import net.jsign.jca.GoogleCloudSigningService;
import net.jsign.jca.HashiCorpVaultSigningService;
import net.jsign.jca.OpenPGPCardSigningService;
import net.jsign.jca.OracleCloudCredentials;
import net.jsign.jca.OracleCloudSigningService;
import net.jsign.jca.PIVCardSigningService;
import net.jsign.jca.SigningServiceJcaProvider;

/**
 * Type of a keystore.
 *
 * @since 5.0
 */
public enum KeyStoreType {

    /** Not a keystore, a private key file and a certificate file are provided separately and assembled into an in-memory keystore */
    NONE(true, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keyfile() == null) {
                throw new IllegalArgumentException("keyfile " + params.parameterName() + " must be set");
            }
            if (!params.keyfile().exists()) {
                throw new IllegalArgumentException("The keyfile " + params.keyfile() + " couldn't be found");
            }
            if (params.certfile() == null) {
                throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
            }
            if (!params.certfile().exists()) {
                throw new IllegalArgumentException("The certfile " + params.certfile() + " couldn't be found");
            }
        }

        @Override
        KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException {
            // load the certificate chain
            Certificate[] chain;
            try {
                chain = CertificateUtils.loadCertificateChain(params.certfile());
            } catch (Exception e) {
                throw new KeyStoreException("Failed to load the certificate from " + params.certfile(), e);
            }

            // load the private key
            PrivateKey privateKey;
            try {
                privateKey = PrivateKeyUtils.load(params.keyfile(), params.keypass() != null ? params.keypass() : params.storepass());
            } catch (Exception e) {
                throw new KeyStoreException("Failed to load the private key from " + params.keyfile(), e);
            }

            // build the in-memory keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            try {
                ks.load(null, null);
                String keypass = params.keypass();
                if (keypass == null) {
                    keypass = params.storepass();
                }
                ks.setKeyEntry("jsign", privateKey, keypass != null ? keypass.toCharArray() : new char[0], chain);
            } catch (Exception e) {
                throw new KeyStoreException(e);
            }

            return ks;
        }
    },

    /** Java keystore */
    JKS(true, true, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must be set");
            }
        }
    },

    /** JCE keystore */
    JCEKS(true, true, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must be set");
            }
        }
    },

    /** PKCS#12 keystore */
    PKCS12(true, true, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must be set");
            }
        }
    },

    /**
     * PKCS#11 hardware token. The keystore parameter specifies either the name of the provider defined
     * in <code>jre/lib/security/java.security</code> or the path to the
     * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html#Config">SunPKCS11 configuration file</a>.
     */
    PKCS11(false, true, true) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must be set");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            // the keystore parameter is either the provider name or the SunPKCS11 configuration file
            if (params.createFile(params.keystore()).exists()) {
                return ProviderUtils.createSunPKCS11Provider(params.keystore());
            } else if (params.keystore().startsWith("SunPKCS11-")) {
                Provider provider = Security.getProvider(params.keystore());
                if (provider == null) {
                    throw new IllegalArgumentException("Security provider " + params.keystore() + " not found");
                }
                return provider;
            } else {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security");
            }
        }
    },

    /**
     * OpenPGP card. OpenPGP cards contain up to 3 keys, one for signing, one for encryption, and one for authentication.
     * All of them can be used for code signing (except encryption keys based on an elliptic curve). The alias
     * to select the key is either, <code>SIGNATURE</code>, <code>ENCRYPTION</code> or <code>AUTHENTICATION</code>.
     * This keystore can be used with a Nitrokey (non-HSM models) or a Yubikey. If multiple devices are connected,
     * the keystore parameter can be used to specify the name of the one to use. This keystore type doesn't require
     * any external library to be installed.
     */
    OPENPGP(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.storepass() == null) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the PIN");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            try {
                return new SigningServiceJcaProvider(new OpenPGPCardSigningService(params.keystore(), params.storepass(), params.certfile() != null ? getCertificateStore(params) : null));
            } catch (CardException e) {
                throw new IllegalStateException("Failed to initialize the OpenPGP card", e);
            }
        }
    },

    /**
     * OpenSC supported smart card.
     * This keystore requires the installation of <a href="https://github.com/OpenSC/OpenSC">OpenSC</a>.
     * If multiple devices are connected, the keystore parameter can be used to specify the name of the one to use.
     */
    OPENSC(false, true, true) {
        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return OpenSC.getProvider(params.keystore());
        }
    },

    /**
     * PIV card. PIV cards contain up to 24 private keys and certificates. The alias to select the key is either,
     * <code>AUTHENTICATION</code>, <code>SIGNATURE</code>, <code>KEY_MANAGEMENT</code>, <code>CARD_AUTHENTICATION</code>,
     * or <code>RETIRED&lt;1-20&gt;</code>. Slot numbers are also accepted (for example <code>9c</code> for the digital
     * signature key). If multiple devices are connected, the keystore parameter can be used to specify the name
     * of the one to use. This keystore type doesn't require any external library to be installed.
     */
    PIV(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.storepass() == null) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the PIN");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            try {
                return new SigningServiceJcaProvider(new PIVCardSigningService(params.keystore(), params.storepass(), params.certfile() != null ? getCertificateStore(params) : null));
            } catch (CardException e) {
                throw new IllegalStateException("Failed to initialize the PIV card", e);
            }
        }
    },

    /**
     * Nitrokey HSM. This keystore requires the installation of <a href="https://github.com/OpenSC/OpenSC">OpenSC</a>.
     * Other Nitrokeys based on the OpenPGP card standard are also supported with this storetype, but an X.509
     * certificate must be imported into the Nitrokey (using the gnupg writecert command). Keys without certificates
     * are ignored. Otherwise the {@link #OPENPGP} type should be used.
     */
    NITROKEY(false, true, true) {
        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return OpenSC.getProvider(params.keystore() != null ? params.keystore() : "Nitrokey");
        }
    },

    /**
     * YubiKey PIV. This keystore requires the ykcs11 library from the <a href="https://developers.yubico.com/yubico-piv-tool/">Yubico PIV Tool</a>
     * to be installed at the default location. On Windows, the path to the library must be specified in the
     * <code>PATH</code> environment variable.
     */
    YUBIKEY(false, true, true) {
        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return YubiKey.getProvider();
        }

        @Override
        Set<String> getAliases(KeyStore keystore) throws KeyStoreException {
            Set<String> aliases = super.getAliases(keystore);
            // the attestation certificate is never used for signing
            aliases.remove("X.509 Certificate for PIV Attestation");
            return aliases;
        }
    },

    /**
     * AWS Key Management Service (KMS). AWS KMS stores only the private key, the certificate must be provided
     * separately. The keystore parameter references the AWS region.
     *
     * <p>The AWS access key, secret key, and optionally the session token, are concatenated and used as
     * the storepass parameter; if the latter is not provided, Jsign attempts to fetch the credentials from
     * the environment variables (<code>AWS_ACCESS_KEY_ID</code>, <code>AWS_SECRET_ACCESS_KEY</code> and
     * <code>AWS_SESSION_TOKEN</code>) or from the IMDSv2 service when running on an AWS EC2 instance.</p>
     *
     * <p>In any case, the credentials must allow the following actions: <code>kms:ListKeys</code>,
     * <code>kms:DescribeKey</code> and <code>kms:Sign</code>.</p>
     * */
    AWS(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the AWS region");
            }
            if (params.certfile() == null) {
                throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            AmazonCredentials credentials;
            if (params.storepass() != null) {
                credentials = AmazonCredentials.parse(params.storepass());
            } else {
                try {
                    credentials = AmazonCredentials.getDefault();
                } catch (UnknownServiceException e) {
                    throw new IllegalArgumentException("storepass " + params.parameterName()
                            + " must specify the AWS credentials: <accessKey>|<secretKey>[|<sessionToken>]"
                            + ", when not running from an EC2 instance (" + e.getMessage() + ")", e);
                } catch (IOException e) {
                    throw new RuntimeException("An error occurred while fetching temporary credentials from IMDSv2 service", e);
                }
            }

            return new SigningServiceJcaProvider(new AmazonSigningService(params.keystore(), credentials, getCertificateStore(params)));
        }
    },

    /**
     * Azure Key Vault. The keystore parameter specifies the name of the key vault, either the short name
     * (e.g. <code>myvault</code>), or the full URL (e.g. <code>https://myvault.vault.azure.net</code>).
     * The Azure API access token is used as the keystore password.
     */
    AZUREKEYVAULT(false, true, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Azure vault name");
            }
            if (params.storepass() == null) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the Azure API access token");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return new SigningServiceJcaProvider(new AzureKeyVaultSigningService(params.keystore(), params.storepass()));
        }
    },

    /**
     * DigiCert ONE. Certificates and keys stored in the DigiCert ONE Secure Software Manager can be used directly
     * without installing the DigiCert client tools. The API key, the PKCS#12 keystore holding the client certificate
     * and its password are combined to form the storepass parameter: <code>&lt;api-key&gt;|&lt;keystore&gt;|&lt;password&gt;</code>.
     */
    DIGICERTONE(false, true, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.storepass() == null || params.storepass().split("\\|").length != 3) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            String[] elements = params.storepass().split("\\|");
            return new SigningServiceJcaProvider(new DigiCertOneSigningService(params.keystore(), elements[0], params.createFile(elements[1]), elements[2]));
        }
    },

    /**
     * SSL.com eSigner. The SSL.com username and password are used as the keystore password (<code>&lt;username&gt;|&lt;password&gt;</code>),
     * and the base64 encoded TOTP secret is used as the key password.
     */
    ESIGNER(false, true, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.storepass() == null || !params.storepass().contains("|")) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the SSL.com username and password: <username>|<password>");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            String[] elements = params.storepass().split("\\|", 2);
            String endpoint = params.keystore() != null ? params.keystore() : "https://cs.ssl.com";
            try {
                return new SigningServiceJcaProvider(new ESignerSigningService(endpoint, elements[0], elements[1]));
            } catch (IOException e) {
                throw new IllegalStateException("Authentication failed with SSL.com", e);
            }
        }

        @Override
        boolean reuseKeyStorePassword() {
            return false;
        }
    },

    /**
     * Google Cloud KMS. Google Cloud KMS stores only the private key, the certificate must be provided separately.
     * The keystore parameter references the path of the keyring. The alias can specify either the full path of the key,
     * or only the short name. If the version is omitted the most recent one will be picked automatically.
     */
    GOOGLECLOUD(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Goole Cloud keyring");
            }
            if (!params.keystore().matches("projects/[^/]+/locations/[^/]+/keyRings/[^/]+")) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the path of the keyring (projects/{projectName}/locations/{location}/keyRings/{keyringName})");
            }
            if (params.storepass() == null) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the Goole Cloud API access token");
            }
            if (params.certfile() == null) {
                throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return new SigningServiceJcaProvider(new GoogleCloudSigningService(params.keystore(), params.storepass(), getCertificateStore(params)));
        }
    },

    /**
     * HashiCorp Vault secrets engine (GCP only). Since Google Cloud KMS stores only the private key, the certificate
     * must be provided separately. The keystore parameter references the URL of the HashiCorp Vault secrets engine
     * (<code>https://vault.example.com/v1/gcpkms</code>). The alias specifies the name of the key in Vault and the key version
     * in Google Cloud separated by a colon character (<code>mykey:1</code>).
     */
    HASHICORPVAULT(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the HashiCorp Vault secrets engine URL");
            }
            if (params.storepass() == null) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the HashiCorp Vault token");
            }
            if (params.certfile() == null) {
                throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return new SigningServiceJcaProvider(new HashiCorpVaultSigningService(params.keystore(), params.storepass(), getCertificateStore(params)));
        }
    },

    /**
     * SafeNet eToken
     * This keystore requires the installation of the SafeNet Authentication Client.
     */
    ETOKEN(false, true, true) {
        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return SafeNetEToken.getProvider();
        }
    },

    /**
     * Oracle Cloud Infrastructure Key Management Service. This keystore requires the <a href="https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm">configuration file</a>
     * or the <a href="https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clienvironmentvariables.htm">environment
     * variables</a> used by the OCI CLI. The storepass parameter specifies the path to the configuration file
     * (<code>~/.oci/config</code> by default). If the configuration file contains multiple profiles, the name of the
     * non-default profile to use is appended to the storepass (for example <code>~/.oci/config|PROFILE</code>).
     * The keypass parameter may be used to specify the passphrase of the key file used for signing the requests to
     * the OCI API if it isn't set in the configuration file.
     *
     * <p>The certificate must be provided separately using the certfile parameter. The alias specifies the OCID
     * of the key.</p>
     */
    ORACLECLOUD(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.certfile() == null) {
                throw new IllegalArgumentException("certfile " + params.parameterName() + " must be set");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            OracleCloudCredentials credentials = new OracleCloudCredentials();
            try {
                File config = null;
                String profile = null;
                if (params.storepass() != null) {
                    String[] elements = params.storepass().split("\\|", 2);
                    config = new File(elements[0]);
                    if (elements.length > 1) {
                        profile = elements[1];
                    }
                }
                credentials.load(config, profile);
                credentials.loadFromEnvironment();
                if (params.keypass() != null) {
                    credentials.setPassphrase(params.keypass());
                }
            } catch (IOException e) {
                throw new RuntimeException("An error occurred while fetching the Oracle Cloud credentials", e);
            }
            return new SigningServiceJcaProvider(new OracleCloudSigningService(credentials, getCertificateStore(params)));
        }
    },

    /**
     * Azure Trusted Signing Service. The keystore parameter specifies the API endpoint (for example
     * <code>weu.codesigning.azure.net</code>). The Azure API access token is used as the keystore password,
     * it can be obtained using the Azure CLI with:
     *
     * <pre>  az account get-access-token --resource https://codesigning.azure.net</pre>
     */
    TRUSTEDSIGNING(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Azure endpoint (<region>.codesigning.azure.net)");
            }
            if (params.storepass() == null) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the Azure API access token");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return new SigningServiceJcaProvider(new AzureTrustedSigningService(params.keystore(), params.storepass()));
        }
    },

    GARASIGN(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.storepass() == null || params.storepass().split("\\|").length > 3) {
                throw new IllegalArgumentException("storepass " + params.parameterName() + " must specify the GaraSign username/password and/or the path to the keystore containing the TLS client certificate: <username>|<password>, <certificate>, or <username>|<password>|<certificate>");
            }
        }

        @Override
        Provider getProvider(KeyStoreBuilder params) {
            String[] elements = params.storepass().split("\\|");
            String username = null;
            String password = null;
            String certificate = null;
            if (elements.length == 1) {
                certificate = elements[0];
            } else if (elements.length == 2) {
                username = elements[0];
                password = elements[1];
            } else if (elements.length == 3) {
                username = elements[0];
                password = elements[1];
                certificate = elements[2];
            }

            GaraSignCredentials credentials = new GaraSignCredentials(username, password, certificate, params.keypass());
            return new SigningServiceJcaProvider(new GaraSignSigningService(params.keystore(), credentials));
        }
    };


    /** Tells if the keystore is contained in a local file */
    private final boolean fileBased;

    /** Tells if the keystore contains the certificate */
    private final boolean certificate;

    /** Tells if the keystore is actually a PKCS#11 keystore */
    private final boolean pkcs11;

    KeyStoreType(boolean fileBased, boolean certificate, boolean pkcs11) {
        this.fileBased = fileBased;
        this.certificate = certificate;
        this.pkcs11 = pkcs11;
    }

    boolean hasCertificate() {
        return certificate;
    }

    /**
     * Validates the keystore parameters.
     */
    void validate(KeyStoreBuilder params) throws IllegalArgumentException {
    }

    /**
     * Returns the security provider to use the keystore.
     */
    Provider getProvider(KeyStoreBuilder params) {
        return null;
    }

    /**
     * Build the keystore.
     */
    KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException {
        KeyStore ks;
        try {
            KeyStoreType storetype = pkcs11 ? PKCS11 : this;
            if (provider != null) {
                ks = KeyStore.getInstance(storetype.name(), provider);
            } else {
                ks = KeyStore.getInstance(storetype.name());
            }
        } catch (KeyStoreException e) {
            throw new KeyStoreException("keystore type '" + name() + "' is not supported" + (provider != null ? " with security provider " + provider.getName() : ""), e);
        }

        if (fileBased && (params.keystore() == null || !params.createFile(params.keystore()).exists())) {
            throw new KeyStoreException("The keystore " + params.keystore() + " couldn't be found");
        }

        try {
            try (FileInputStream in = fileBased ? new FileInputStream(params.createFile(params.keystore())) : null) {
                ks.load(in, params.storepass() != null ? params.storepass().toCharArray() : null);
            }
        } catch (Exception e) {
            throw new KeyStoreException("Unable to load the keystore " + params.keystore(), e);
        }

        return ks;
    }

    /**
     * Returns the aliases of the keystore available for signing.
     */
    Set<String> getAliases(KeyStore keystore) throws KeyStoreException {
        return new LinkedHashSet<>(Collections.list(keystore.aliases()));
    }

    /**
     * Tells if the keystore password can be reused as the key password.
     */
    boolean reuseKeyStorePassword() {
        return true;
    }

    /**
     * Guess the type of the keystore from the header or the extension of the file.
     *
     * @param path   the path to the keystore
     */
    static KeyStoreType of(File path) {
        // guess the type of the keystore from the header of the file
        if (path.exists()) {
            try (FileInputStream in = new FileInputStream(path)) {
                byte[] header = new byte[4];
                in.read(header);
                ByteBuffer buffer = ByteBuffer.wrap(header);
                if (buffer.get(0) == 0x30) {
                    return PKCS12;
                } else if ((buffer.getInt(0) & 0xFFFFFFFFL) == 0xCECECECEL) {
                    return JCEKS;
                } else if ((buffer.getInt(0) & 0xFFFFFFFFL) == 0xFEEDFEEDL) {
                    return JKS;
                }
            } catch (IOException e) {
                throw new RuntimeException("Unable to load the keystore " + path, e);
            }
        }

        // guess the type of the keystore from the extension of the file
        String filename = path.getName().toLowerCase();
        if (filename.endsWith(".p12") || filename.endsWith(".pfx")) {
            return PKCS12;
        } else if (filename.endsWith(".jceks")) {
            return JCEKS;
        } else if (filename.endsWith(".jks")) {
            return JKS;
        } else {
            return null;
        }
    }

    private static Function<String, Certificate[]> getCertificateStore(KeyStoreBuilder params) {
        return alias -> {
            if (alias == null || alias.isEmpty()) {
                return null;
            }

            try {
                return CertificateUtils.loadCertificateChain(params.certfile());
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("Failed to load the certificate from " + params.certfile(), e);
            }
        };
    }
}
