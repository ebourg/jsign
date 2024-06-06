/**
 * Copyright 2023 Maria Merkel
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

package net.jsign.jca;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Map;
import java.util.function.Function;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the HashiCorp Vault API. It supports the Google Cloud KMS and Transit secrets engines only.
 *
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/gcpkms">HashiCorp Vault API - Google Cloud KMS Secrets Engine</a>
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/transit">HashiCorp Vault API - Transit Secrets Engine</a>
 * @since 5.0
 */
public class HashiCorpVaultSigningService implements SigningService {

    private static final Logger logger = Logger.getLogger(HashiCorpVaultSigningService.class.getName());

    private final Function<String, Certificate[]> certificateStore;

    /** Cache of private keys indexed by id */
    private final Map<String, SigningServicePrivateKey> keys = new HashMap<>();

    private final RESTClient client;

    /** Specifies whether the key store uses the Google Cloud KMS secret engine,
     * or the native HashiCorp Vault Transit secret engine. */
    private boolean googleCloudKMS;

    /**
     * Creates a new HashiCorp Vault signing service.
     *
     * @param engineURL        the URL of the HashiCorp Vault secrets engine
     * @param token            the HashiCorp Vault token
     * @param certificateStore provides the certificate chain for the keys
     */
    public HashiCorpVaultSigningService(String engineURL, String token, Function<String, Certificate[]> certificateStore) {
        this.certificateStore = certificateStore;
        this.client = new RESTClient(engineURL.endsWith("/") ? engineURL : engineURL + "/")
                .authentication(conn -> conn.setRequestProperty("Authorization", "Bearer " + token));
        this.googleCloudKMS = true;
    }

    @Override
    public String getName() {
        return "HashiCorpVault";
    }

    /**
     * Returns the list of key names available in the secrets engine.
     *
     * NOTE: This will return the key name only, not the key name and version.
     * HashiCorp Vault does not provide a function to retrieve the key version.
     * The key version will need to be appended to the key name when using the key.
     *
     * @return list of key names
     */
    @SuppressWarnings("unchecked")
    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            Map<String, ?> response = client.get("keys?list=true");
            Object[] keys = ((Map<String, Object[]>) response.get("data")).get("keys");
            for (Object key : keys) {
                aliases.add((String) key);
            }
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }

        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return certificateStore.apply(alias);
    }

    @SuppressWarnings("unchecked")
    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        if (keys.containsKey(alias)) {
            return keys.get(alias);
        }

        if (!alias.contains(":")) {
            // Key alias does not contain version, latest version will be used.
            throw new UnrecoverableKeyException("Unable to fetch HashiCorp Vault private key '" + alias + "' (missing key version)");
        }

        String algorithm = null;
        String aliasWithoutVersion = null;

        try {
            aliasWithoutVersion = alias.substring(0, alias.indexOf(":"));
            Map<String, ?> response = client.get("keys/" + aliasWithoutVersion);

            if (response == null || !response.containsKey("data")) {
                throw new IllegalArgumentException("Response or 'data' key is null.");
            }

            if (response.containsKey("warnings") && response.get("warnings") != null) {
                logger.log(Level.WARNING, String.format("Vault responded with warnings: %s", response.get("warnings")));
            }

            if (response.containsKey("error")) {
                throw new IllegalArgumentException(String.format("Vault responded with error: %s", response.get("error")));
            }

            Map<String, String> data;
            try {
                data = (Map<String, String>) response.get("data");
            } catch (ClassCastException e) {
                throw new IllegalArgumentException("The 'data' key does not contain a Map<String, String>.", e);
            }

            // Check for "algorithm" or "type" for "gcpkms" or "transit" respectively
            if (data == null || (!data.containsKey("algorithm") && !data.containsKey("type"))) {
                throw new IllegalArgumentException("'data' does not contain 'algorithm' or 'type' key.");
            }

            // Check for "algorithm" or "type" and assign the value to `algorithm`
            if (data.containsKey("algorithm")) {
                algorithm = data.get("algorithm");
            } else if (data.containsKey("type")) {
                algorithm = data.get("type");
                this.googleCloudKMS = false;
            }

            if (algorithm == null) {
                throw new IllegalArgumentException("'algorithm' or 'type' is null.");
            }

            /*
             * HashiCorp Vault Google Cloud KMS key type format : 'rsa_sign_pkcs1_<BITS>_<DIGEST_ALGORITHM>'
             * HashiCorp Vault Transit key type format          : 'rsa-<BITS>'
             */
            if (this.googleCloudKMS) {
                algorithm = algorithm.substring(0, algorithm.indexOf("_")).toUpperCase();
            }
            else {
                algorithm = algorithm.substring(0, algorithm.indexOf("-")).toUpperCase();
            }

        } catch (ClassCastException | IllegalArgumentException e) {
            logger.log(Level.SEVERE, "Invalid response format while fetching algorithm for key alias '" + alias +"': ", e.getMessage());
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch HashiCorp Vault private key '" + alias + "'").initCause(e);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "IO Exception while fetching algorithm for key alias '" + alias + "': ", e.getMessage());
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch HashiCorp Vault private key '" + alias + "'").initCause(e);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected exception while fetching algorithm for key alias '" + alias + "': ", e.getMessage());
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unexpected exception while fetching HashiCorp Vault private key '" + alias + "'").initCause(e);
        }

        SigningServicePrivateKey key = new SigningServicePrivateKey(alias, algorithm, this);
        keys.put(alias, key);
        return key;
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        String alias = privateKey.getId();
        String keyName = alias.substring(0, alias.indexOf(":"));
        String keyVersion = alias.substring(alias.indexOf(":") + 1);

        Map<String, Object> request = new HashMap<>();
        request.put("key_version", keyVersion);

        if (this.googleCloudKMS) {
            request.put("digest", Base64.getEncoder().encodeToString(data));
        }
        else {
            String shaType;
            try {
                shaType = digestAlgorithm.toString().split("SHA")[1];
            } catch (RuntimeException e) {
                logger.log(Level.WARNING, "Could not determine SHA type - defaulting to SHA256");
                shaType = "256";
            }

            request.put("input", Base64.getEncoder().encodeToString(data));
            request.put("prehashed", true);
            request.put("hash_algorithm", String.format("sha2-%s", shaType));

            // By default, RSA sign in HashiCorp Vault Transit uses RSA-PSS.
            if (privateKey.getAlgorithm().equals("RSA")) {
                request.put("signature_algorithm", "pkcs1v15");
            }
        }

        try {
            Map<String, ?> response = client.post("sign/" + keyName, JsonWriter.format(request));

            if (response == null || !response.containsKey("data")) {
                throw new IllegalArgumentException("Response or 'data' key is null.");
            }

            if (response.containsKey("warnings") && response.get("warnings") != null) {
                logger.log(Level.WARNING, String.format("Vault responded with warnings: %s", response.get("warnings")));
            }

            if (response.containsKey("error")) {
                throw new IllegalArgumentException(String.format("Vault responded with error: %s", response.get("error")));
            }

            @SuppressWarnings("unchecked") Map<String, String> response_data = (Map<String, String>) response.get("data");
            if (response_data == null || !response_data.containsKey("signature")) {
                throw new IllegalArgumentException("'data' or 'signature' key is null.");
            }

            String vault_signature = response_data.get("signature");
            if (vault_signature == null) {
                throw new IllegalArgumentException("Vault signature is null.");
            }

            /*
             *  HashiCorp Vault Google Cloud KMS signature format   : '<BASE64_SIGNATURE>'
             *  HashiCorp Vault Transit signature format            : 'vault:v<KEY_VERSION>:<BASE64_SIGNATURE>'
             */
            String signature;
            if (this.googleCloudKMS) {
                signature = vault_signature;
            }
            else {
                String[] signatureParts = vault_signature.split(":");
                if (signatureParts.length != 3) {
                    throw new IllegalArgumentException("Invalid vault signature format.");
                }
                signature = signatureParts[2];
            }

            return Base64.getDecoder().decode(signature);

        } catch (IllegalArgumentException | ClassCastException e) {
            logger.log(Level.SEVERE, "Invalid response format: ", e.getMessage());
            throw new GeneralSecurityException("Invalid response format.", e);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "IO Exception during signing: ", e.getMessage());
            throw new GeneralSecurityException("IO Exception during signing.", e);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected exception: ", e.getMessage());
            throw new GeneralSecurityException("Unexpected exception during signing.", e);
        }
    }
}
