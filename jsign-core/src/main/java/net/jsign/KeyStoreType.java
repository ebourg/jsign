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

import net.jsign.jca.AmazonSigningService;
import net.jsign.jca.AzureKeyVaultSigningService;
import net.jsign.jca.DigiCertOneSigningService;
import net.jsign.jca.ESignerSigningService;
import net.jsign.jca.GoogleCloudSigningService;
import net.jsign.jca.HashiCorpVaultSigningService;
import net.jsign.jca.OpenPGPCardSigningService;
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

    /** PKCS#11 hardware token */
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

    /** OpenPGP card */
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
                Function<String, Certificate[]> certificateStore = alias -> {
                    try {
                        return CertificateUtils.loadCertificateChain(params.certfile());
                    } catch (IOException | CertificateException e) {
                        throw new RuntimeException("Failed to load the certificate from " + params.certfile(), e);
                    }
                };
                return new SigningServiceJcaProvider(new OpenPGPCardSigningService(params.storepass(), params.certfile() != null ? certificateStore : null));
            } catch (CardException e) {
                throw new IllegalStateException("Failed to initialize the OpenPGP card", e);
            }
        }
    },

    /** OpenSC supported smart card */
    OPENSC(false, true, true) {
        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return OpenSC.getProvider(params.keystore());
        }
    },

    /** Nitrokey HSM */
    NITROKEY(false, true, true) {
        @Override
        Provider getProvider(KeyStoreBuilder params) {
            return OpenSC.getProvider(params.keystore() != null ? params.keystore() : "Nitrokey");
        }
    },

    /** YubiKey PIV */
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

    /** AWS KMS */
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
            return new SigningServiceJcaProvider(new AmazonSigningService(params.keystore(), params.storepass(), alias -> {
                try {
                    return CertificateUtils.loadCertificateChain(params.certfile());
                } catch (IOException | CertificateException e) {
                    throw new RuntimeException("Failed to load the certificate from " + params.certfile(), e);
                }
            }, params.parameterName()));
        }
    },

    /** Azure Key Vault */
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

    /** DigiCert ONE */
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
            return new SigningServiceJcaProvider(new DigiCertOneSigningService(elements[0], params.createFile(elements[1]), elements[2]));
        }
    },

    /** SSL.com eSigner */
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

    /** Google Cloud KMS */
    GOOGLECLOUD(false, false, false) {
        @Override
        void validate(KeyStoreBuilder params) {
            if (params.keystore() == null) {
                throw new IllegalArgumentException("keystore " + params.parameterName() + " must specify the Goole Cloud keyring");
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
            return new SigningServiceJcaProvider(new GoogleCloudSigningService(params.keystore(), params.storepass(), alias -> {
                try {
                    return CertificateUtils.loadCertificateChain(params.certfile());
                } catch (IOException | CertificateException e) {
                    throw new RuntimeException("Failed to load the certificate from " + params.certfile(), e);
                }
            }));
        }
    },

    /** HashiCorp Vault secrets engine (GCP only) */
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
            return new SigningServiceJcaProvider(new HashiCorpVaultSigningService(params.keystore(), params.storepass(), alias -> {
                try {
                    return CertificateUtils.loadCertificateChain(params.certfile());
                } catch (IOException | CertificateException e) {
                    throw new RuntimeException("Failed to load the certificate from " + params.certfile(), e);
                }
            }));
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
}
