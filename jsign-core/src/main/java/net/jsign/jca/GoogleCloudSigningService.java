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
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
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

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import org.apache.commons.io.IOUtils;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Google Cloud Key Management API.
 *
 * @since 4.0
 * @see <a href="https://cloud.google.com/kms/docs/reference/rest">Cloud Key Management Service (KMS) API</a>
 */
public class GoogleCloudSigningService implements SigningService {

    /** The name of the keyring */
    private final String keyring;

    /** The Google Cloud API access token */
    private final String token;

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    /**
     * Creates a new Google Cloud signing service.
     *
     * @param keyring          the path of the keyring (for example <tt>projects/first-rain-123/locations/global/keyRings/mykeyring</tt>)
     * @param token            the Google Cloud API access token
     * @param certificateStore provides the certificate chain for the keys
     */
    public GoogleCloudSigningService(String keyring, String token, Function<String, Certificate[]> certificateStore) {
        this.keyring = keyring;
        this.token = token;
        this.certificateStore = certificateStore;
    }

    @Override
    public String getName() {
        return "GoogleCloud";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            Map<String, ?> response = get(keyring + "/cryptoKeys");
            Object[] cryptoKeys = (Object[]) response.get("cryptoKeys");
            for (Object cryptoKey : cryptoKeys) {
                String name = (String) ((Map) cryptoKey).get("name");
                aliases.add(name.substring(name.lastIndexOf("/") + 1));
            }
        } catch (GoogleCloudException | IOException e) {
            throw new KeyStoreException(e);
        }

        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) {
        return certificateStore.apply(alias);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException {
        // check if the alias is absolute or relative to the keyring
        if (!alias.startsWith("projects/")) {
            alias = keyring + "/cryptoKeys/" + alias;
        }

        String algorithm;

        try {
            if (alias.contains("cryptoKeyVersions")) {
                // full key with version specified
                Map<String, ?> response = get(alias);
                algorithm = (String) response.get("algorithm");
            } else {
                // key version not specified, find the most recent
                Map<String, ?> response = get(alias + "/cryptoKeyVersions?filter=state%3DENABLED");
                Object[] cryptoKeyVersions = (Object[]) response.get("cryptoKeyVersions");
                if (cryptoKeyVersions == null || cryptoKeyVersions.length == 0) {
                    throw new UnrecoverableKeyException("Unable to fetch Google Cloud private key '" + alias + "', no version found");
                }

                Map<String, ?> cryptoKeyVersion = (Map) cryptoKeyVersions[cryptoKeyVersions.length - 1];
                alias = (String) cryptoKeyVersion.get("name");
                algorithm = (String) cryptoKeyVersion.get("algorithm");
            }
        } catch (GoogleCloudException | IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch Google Cloud private key '" + alias + "'").initCause(e);
        }

        algorithm = algorithm.substring(0, algorithm.indexOf("_")); // RSA_SIGN_PKCS1_2048_SHA256 -> RSA

        return new SigningServicePrivateKey(alias, algorithm);
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest();

        Map<String, String> digest = new HashMap<>();
        digest.put(digestAlgorithm.name().toLowerCase(), Base64.getEncoder().encodeToString(data));
        Map<String, Object> request = new HashMap<>();
        request.put("digest", digest);

        try {
            Map<String, Object> args = new HashMap<>();
            args.put(JsonWriter.TYPE, "false");
            Map<String, ?> response = post(privateKey.getId() + ":asymmetricSign", JsonWriter.objectToJson(request, args));
            String signature = (String) response.get("signature");

            return Base64.getDecoder().decode(signature);
        } catch (GoogleCloudException | IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private Map<String, ?> get(String resource) throws GoogleCloudException, IOException {
        return query("GET", resource, null);
    }

    private Map<String, ?> post(String resource, String body) throws GoogleCloudException, IOException {
        return query("POST", resource, body);
    }

    private Map<String, ?> query(String method, String resource, String body) throws GoogleCloudException, IOException {
        URL url = new URL("https://cloudkms.googleapis.com/v1/" + resource);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setRequestMethod(method);
        if (body != null) {
            byte[] data = body.getBytes(StandardCharsets.UTF_8);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Content-Length", String.valueOf(data.length));
            conn.getOutputStream().write(data);
        }

        int responseCode = conn.getResponseCode();
        String contentType = conn.getHeaderField("Content-Type");
        if (responseCode < 400) {
            String response = IOUtils.toString(conn.getInputStream(), StandardCharsets.UTF_8);

            return JsonReader.jsonToMaps(response);
        } else {
            String error = IOUtils.toString(conn.getErrorStream(), StandardCharsets.UTF_8);
            if (contentType != null && contentType.startsWith("application/json")) {
                throw new GoogleCloudException(JsonReader.jsonToMaps(error));
            } else {
                throw new IOException("HTTP Error " + responseCode);
            }
        }
    }
}
