/**
 * Copyright 2021 Emmanuel Bourg
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

import com.cedarsoftware.util.io.JsonWriter;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Google Cloud Key Management API.
 *
 * <p>The key alias can take one of the following forms:</p>
 *  <ul>
 *   <li>The absolute path of the key with the exact version specified:
 *       <tt>projects/first-rain-123/locations/global/keyRings/mykeyring/cryptoKeys/mykey/cryptoKeyVersions/2</tt></li>
 *   <li>The absolute path of the key without the version specified, the first version enabled will be used:
 *       <tt>projects/first-rain-123/locations/global/keyRings/mykeyring/cryptoKeys/mykey</tt></li>
 *   <li>The path of the key relatively to the keyring with the version specified: <tt>mykey/cryptoKeyVersions/2</tt></li>
 *   <li>The path of the key relatively to the keyring without the version specified: <tt>mykey</tt></li>
 * </ul>
 *
 * <p>When the version of the key is specified, it's also possible to append the algorithm of the key, this saves
 * a round-trip and reduces the risk of hitting a read request limit when signing a large number of files:
 * <tt>mykey/cryptoKeyVersions/2:ECDSA</tt></p>
 *
 * @since 4.0
 * @see <a href="https://cloud.google.com/kms/docs/reference/rest">Cloud Key Management Service (KMS) API</a>
 */
public class GoogleCloudSigningService implements SigningService {

    /** The name of the keyring */
    private final String keyring;

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    /** Cache of private keys indexed by id */
    private final Map<String, SigningServicePrivateKey> keys = new HashMap<>();

    private final RESTClient client;

    /**
     * Creates a new Google Cloud signing service.
     *
     * @param keyring          the path of the keyring (for example <tt>projects/first-rain-123/locations/global/keyRings/mykeyring</tt>)
     * @param token            the Google Cloud API access token
     * @param certificateStore provides the certificate chain for the keys
     */
    public GoogleCloudSigningService(String keyring, String token, Function<String, Certificate[]> certificateStore) {
        this.keyring = keyring;
        this.certificateStore = certificateStore;
        this.client = new RESTClient("https://cloudkms.googleapis.com/v1/", conn -> conn.setRequestProperty("Authorization", "Bearer " + token));
    }

    @Override
    public String getName() {
        return "GoogleCloud";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            Map<String, ?> response = client.get(keyring + "/cryptoKeys");
            Object[] cryptoKeys = (Object[]) response.get("cryptoKeys");
            for (Object cryptoKey : cryptoKeys) {
                String name = (String) ((Map) cryptoKey).get("name");
                aliases.add(name.substring(name.lastIndexOf("/") + 1));
            }
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }

        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) {
        return certificateStore.apply(alias);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        // check if the alias is absolute or relative to the keyring
        if (!alias.startsWith("projects/")) {
            alias = keyring + "/cryptoKeys/" + alias;
        }

        if (keys.containsKey(alias)) {
            return keys.get(alias);
        }

        String algorithm;

        try {
            if (alias.contains("cryptoKeyVersions")) {
                // full key with version specified
                if (alias.contains(":")) {
                    // algorithm appended to the alias
                    algorithm = alias.substring(alias.indexOf(':') + 1) + "_SIGN";
                    alias = alias.substring(0, alias.indexOf(':'));
                } else {
                    Map<String, ?> response = client.get(alias);
                    algorithm = (String) response.get("algorithm");
                }
            } else {
                // key version not specified, find the most recent
                Map<String, ?> response = client.get(alias + "/cryptoKeyVersions?filter=state%3DENABLED");
                Object[] cryptoKeyVersions = (Object[]) response.get("cryptoKeyVersions");
                if (cryptoKeyVersions == null || cryptoKeyVersions.length == 0) {
                    throw new UnrecoverableKeyException("Unable to fetch Google Cloud private key '" + alias + "', no version found");
                }

                Map<String, ?> cryptoKeyVersion = (Map) cryptoKeyVersions[cryptoKeyVersions.length - 1];
                alias = (String) cryptoKeyVersion.get("name");
                algorithm = (String) cryptoKeyVersion.get("algorithm");
            }
        } catch (IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch Google Cloud private key '" + alias + "'").initCause(e);
        }

        algorithm = algorithm.substring(0, algorithm.indexOf("_")); // RSA_SIGN_PKCS1_2048_SHA256 -> RSA

        SigningServicePrivateKey key = new SigningServicePrivateKey(alias, algorithm);
        keys.put(alias, key);
        return key;
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        Map<String, String> digest = new HashMap<>();
        digest.put(digestAlgorithm.name().toLowerCase(), Base64.getEncoder().encodeToString(data));
        Map<String, Object> request = new HashMap<>();
        request.put("digest", digest);

        try {
            Map<String, Object> args = new HashMap<>();
            args.put(JsonWriter.TYPE, "false");
            Map<String, ?> response = client.post(privateKey.getId() + ":asymmetricSign", JsonWriter.objectToJson(request, args));
            String signature = (String) response.get("signature");

            return Base64.getDecoder().decode(signature);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
