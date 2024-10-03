/**
 * Copyright 2023 Maria Merkel
 * Copyright 2024 Eatay Mizrachi
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
import java.util.Map;
import java.util.function.Function;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the HashiCorp Vault API. It supports the Google Cloud KMS and Transit secrets engines.
 *
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/gcpkms">HashiCorp Vault API - Google Cloud KMS Secrets Engine</a>
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/transit">HashiCorp Vault API - Transit Secrets Engine</a>
 * @since 5.0
 */
public class HashiCorpVaultSigningService implements SigningService {

    private final Function<String, Certificate[]> certificateStore;

    /** Cache of private keys indexed by id */
    private final Map<String, SigningServicePrivateKey> keys = new HashMap<>();

    private final RESTClient client;

    /** The type of secret engine */
    private VaultEngine engine;

    private enum VaultEngine { GCPKMS, TRANSIT }

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

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        if (keys.containsKey(alias)) {
            return keys.get(alias);
        }

        if (!alias.contains(":")) {
            throw new UnrecoverableKeyException("Unable to fetch HashiCorp Vault private key '" + alias + "' (missing key version)");
        }

        String algorithm;

        try {
            Map<String, ?> response = client.get("keys/" + alias.substring(0, alias.indexOf(":")));
            Map<String, String> data = (Map<String, String>) response.get("data");

            if (data.containsKey("algorithm")) {
                engine = VaultEngine.GCPKMS;
                // GCPKMS key type format : 'rsa_sign_pkcs1_<BITS>_<DIGEST_ALGORITHM>'
                algorithm = data.get("algorithm");
                algorithm = algorithm.substring(0, algorithm.indexOf("_")).toUpperCase();
            } else if (data.containsKey("type")) {
                engine = VaultEngine.TRANSIT;
                // Transit key type format : 'rsa-<BITS>'
                algorithm = data.get("type");
                algorithm = algorithm.substring(0, algorithm.indexOf("-")).toUpperCase();
            } else {
                throw new UnrecoverableKeyException("Unsupported secret engine");
            }
        } catch (IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch HashiCorp Vault private key '" + alias + "'").initCause(e);
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

        if (engine == VaultEngine.GCPKMS) {
            request.put("digest", Base64.getEncoder().encodeToString(data));
        } else {
            request.put("input", Base64.getEncoder().encodeToString(data));
            request.put("prehashed", true);
            request.put("hash_algorithm", getHashAlgorithm(digestAlgorithm));

            if ("RSA".equals(privateKey.getAlgorithm())) {
                // RSA signatures in HashiCorp Vault Transit use RSA-PSS by default
                request.put("signature_algorithm", "pkcs1v15");
            }
        }

        try {
            Map<String, ?> response = client.post("sign/" + keyName, JsonWriter.format(request));

            Map<String, String> response_data = (Map<String, String>) response.get("data");

            String signature;
            if (engine == VaultEngine.GCPKMS) {
                // Google Cloud KMS signature format: '<BASE64>'
                signature = response_data.get("signature");
            } else {
                // Transit signature format: 'vault:v<KEY_VERSION>:<BASE64>'
                String[] fields = response_data.get("signature").split(":");
                signature = fields[2];
            }

            return Base64.getDecoder().decode(signature);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private String getHashAlgorithm(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA1:
                return "sha1";
            case SHA256:
                return "sha2-256";
            case SHA384:
                return "sha2-384";
            case SHA512:
                return "sha2-512";
            default:
                throw new IllegalArgumentException("Unsupported digest algorithm: " + digestAlgorithm);
        }
    }
}
