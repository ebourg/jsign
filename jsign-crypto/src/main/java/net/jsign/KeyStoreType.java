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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.StreamSupport;

/**
 * Type of a keystore.
 *
 * @since 5.0
 */
public interface KeyStoreType {

    /** Not a keystore, a private key file and a certificate file are provided separately and assembled into an in-memory keystore */
    KeyStoreType NONE = KeyStoreType.valueOf("NONE");

    /** Java keystore */
    KeyStoreType JKS = KeyStoreType.valueOf("JKS");

    /** JCE keystore */
    KeyStoreType JCEKS = KeyStoreType.valueOf("JCEKS");

    /** PKCS#12 keystore */
    KeyStoreType PKCS12 = KeyStoreType.valueOf("PKCS12");

    /**
     * PKCS#11 hardware token. The keystore parameter specifies either the name of the provider defined
     * in <code>jre/lib/security/java.security</code> or the path to the
     * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html#Config">SunPKCS11 configuration file</a>.
     */
    KeyStoreType PKCS11 = KeyStoreType.valueOf("PKCS11");

    /**
     * OpenPGP card. OpenPGP cards contain up to 3 keys, one for signing, one for encryption, and one for authentication.
     * All of them can be used for code signing (except encryption keys based on an elliptic curve). The alias
     * to select the key is either, <code>SIGNATURE</code>, <code>ENCRYPTION</code> or <code>AUTHENTICATION</code>.
     * This keystore can be used with a Nitrokey (non-HSM models) or a Yubikey. If multiple devices are connected,
     * the keystore parameter can be used to specify the name of the one to use. This keystore type doesn't require
     * any external library to be installed.
     */
    KeyStoreType OPENPGP = KeyStoreType.valueOf("OPENPGP");

    /**
     * OpenSC supported smart card.
     * This keystore requires the installation of <a href="https://github.com/OpenSC/OpenSC">OpenSC</a>.
     * If multiple devices are connected, the keystore parameter can be used to specify the name of the one to use.
     */
    KeyStoreType OPENSC = KeyStoreType.valueOf("OPENSC");

    /**
     * PIV card. PIV cards contain up to 24 private keys and certificates. The alias to select the key is either,
     * <code>AUTHENTICATION</code>, <code>SIGNATURE</code>, <code>KEY_MANAGEMENT</code>, <code>CARD_AUTHENTICATION</code>,
     * or <code>RETIRED&lt;1-20&gt;</code>. Slot numbers are also accepted (for example <code>9c</code> for the digital
     * signature key). If multiple devices are connected, the keystore parameter can be used to specify the name
     * of the one to use. This keystore type doesn't require any external library to be installed.
     */
    KeyStoreType PIV = KeyStoreType.valueOf("PIV");

    /**
     * Nitrokey HSM. This keystore requires the installation of <a href="https://github.com/OpenSC/OpenSC">OpenSC</a>.
     * Other Nitrokeys based on the OpenPGP card standard are also supported with this storetype, but an X.509
     * certificate must be imported into the Nitrokey (using the gnupg writecert command). Keys without certificates
     * are ignored. Otherwise the {@link #OPENPGP} type should be used.
     */
    KeyStoreType NITROKEY = KeyStoreType.valueOf("NITROKEY");

    /**
     * YubiKey PIV. This keystore requires the ykcs11 library from the <a href="https://developers.yubico.com/yubico-piv-tool/">Yubico PIV Tool</a>
     * to be installed at the default location. On Windows, the path to the library must be specified in the
     * <code>PATH</code> environment variable.
     */
    KeyStoreType YUBIKEY = KeyStoreType.valueOf("YUBIKEY");

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
    KeyStoreType AWS = KeyStoreType.valueOf("AWS");

    /**
     * Azure Key Vault. The keystore parameter specifies the name of the key vault, either the short name
     * (e.g. <code>myvault</code>), or the full URL (e.g. <code>https://myvault.vault.azure.net</code>).
     * The Azure API access token is used as the keystore password.
     */
    KeyStoreType AZUREKEYVAULT = KeyStoreType.valueOf("AZUREKEYVAULT");

    /**
     * DigiCert ONE. Certificates and keys stored in the DigiCert ONE Secure Software Manager can be used directly
     * without installing the DigiCert client tools. The API key, the PKCS#12 keystore holding the client certificate
     * and its password are combined to form the storepass parameter: <code>&lt;api-key&gt;|&lt;keystore&gt;|&lt;password&gt;</code>.
     */
    KeyStoreType DIGICERTONE = KeyStoreType.valueOf("DIGICERTONE");

    /**
     * SSL.com eSigner. The SSL.com username and password are used as the keystore password (<code>&lt;username&gt;|&lt;password&gt;</code>),
     * and the base64 encoded TOTP secret is used as the key password.
     */
    KeyStoreType ESIGNER = KeyStoreType.valueOf("ESIGNER");

    /**
     * Google Cloud KMS. Google Cloud KMS stores only the private key, the certificate must be provided separately.
     * The keystore parameter references the path of the keyring. The alias can specify either the full path of the key,
     * or only the short name. If the version is omitted the most recent one will be picked automatically.
     */
    KeyStoreType GOOGLECLOUD = KeyStoreType.valueOf("GOOGLECLOUD");

    /**
     * HashiCorp Vault secrets engine (Transit or GCPKMS). The certificate must be provided separately. The keystore
     * parameter references the URL of the HashiCorp Vault secrets engine (<code>https://vault.example.com/v1/gcpkms</code>).
     * The alias parameter specifies the name of the key in Vault. For the Google Cloud KMS secrets engine, the version
     * of the Google Cloud key is appended to the key name, separated by a colon character. (<code>mykey:1</code>).
     */
    KeyStoreType HASHICORPVAULT = KeyStoreType.valueOf("HASHICORPVAULT");

    /**
     * SafeNet eToken
     * This keystore requires the installation of the SafeNet Authentication Client.
     */
    KeyStoreType ETOKEN = KeyStoreType.valueOf("ETOKEN");

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
    KeyStoreType ORACLECLOUD = KeyStoreType.valueOf("ORACLECLOUD");

    /**
     * Azure Trusted Signing Service. The keystore parameter specifies the API endpoint (for example
     * <code>weu.codesigning.azure.net</code>). The Azure API access token is used as the keystore password,
     * it can be obtained using the Azure CLI with:
     *
     * <pre>  az account get-access-token --resource https://codesigning.azure.net</pre>
     */
    KeyStoreType TRUSTEDSIGNING = KeyStoreType.valueOf("TRUSTEDSIGNING");

    KeyStoreType GARASIGN = KeyStoreType.valueOf("GARASIGN");

    /**
     * Keyfactor SignServer. This keystore requires a Plain Signer worker configured to allow client-side hashing (with
     * the properties <code>CLIENTSIDEHASHING</code> or <code>ALLOW_CLIENTSIDEHASHING_OVERRIDE</code> set to true), and
     * the <code>SIGNATUREALGORITHM</code> property set to <code>NONEwithRSA</code> or <code>NONEwithECDSA</code>.
     *
     * <p>The authentication is performed by specifying the username/password or the TLS client certificate in the
     * storepass parameter. If the TLS client certificate is stored in a password protected keystore, the password is
     * specified in the keypass parameter. The keystore parameter references the URL of the SignServer REST API. The
     * alias parameter specifies the id or the name of the worker.</p>
     */
    KeyStoreType SIGNSERVER = KeyStoreType.valueOf("SIGNSERVER");

    /**
     * Returns the name of the keystore type.
     */
    String name();

    /**
     * Validates the keystore parameters.
     */
    default void validate(KeyStoreBuilder params) throws IllegalArgumentException {
    }

    /**
     * Returns the security provider to use the keystore.
     */
    default Provider getProvider(KeyStoreBuilder params) {
        return null;
    }

    /**
     * Build the keystore.
     */
    KeyStore getKeystore(KeyStoreBuilder params, Provider provider) throws KeyStoreException;

    /**
     * Returns the aliases of the keystore available for signing.
     */
    default Set<String> getAliases(KeyStore keystore) throws KeyStoreException {
        return new LinkedHashSet<>(Collections.list(keystore.aliases()));
    }

    /**
     * Returns the storetype with the specified name.
     *
     * @param name the name of the storetype
     * @return the storetype with the specified name
     * @throws IllegalArgumentException if the storetype specified isn't supported
     */
    static KeyStoreType valueOf(String name) {
        for (KeyStoreType storetype : ServiceLoader.load(KeyStoreType.class)) {
            if (name.equals(storetype.name())) {
                return storetype;
            }
        }

        throw new IllegalArgumentException("Unsupported KeyStore type: " + name);
    }

    static KeyStoreType[] values() {
        return StreamSupport.stream(ServiceLoader.load(KeyStoreType.class).spliterator(), false).toArray(KeyStoreType[]::new);
    }
}
