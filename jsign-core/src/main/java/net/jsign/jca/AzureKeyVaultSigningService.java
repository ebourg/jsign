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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cedarsoftware.util.io.JsonReader;
import com.cedarsoftware.util.io.JsonWriter;
import org.apache.commons.io.IOUtils;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Azure KeyVault API.
 *
 * @since 4.0
 * @see <a href="https://docs.microsoft.com/en-us/rest/api/keyvault/">Azure Key Vault REST API reference</a>
 */
public class AzureKeyVaultSigningService implements SigningService {

    /** The name of the key vault */
    private final String vault;

    /** The Azure API access token */
    private final String token;

    /**
     * Mapping between Java and Azure signing algorithms.
     * @see <a href="https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm">Key Vault API - JonWebKeySignatureAlgorithm</a>
     */
    private final Map<String, String> algorithmMapping = new HashMap<>();
    {
        algorithmMapping.put("SHA256withRSA", "RS256");
        algorithmMapping.put("SHA384withRSA", "RS384");
        algorithmMapping.put("SHA512withRSA", "RS512");
        algorithmMapping.put("SHA256withECDSA", "ES256");
        algorithmMapping.put("SHA384withECDSA", "ES384");
        algorithmMapping.put("SHA512withECDSA", "ES512");
        algorithmMapping.put("SHA256withRSA/PSS", "PS256");
        algorithmMapping.put("SHA384withRSA/PSS", "PS384");
        algorithmMapping.put("SHA512withRSA/PSS", "PS512");
    }

    /**
     * Creates a new Azure Key Vault signing service.
     *
     * @param vault the path of the key vault
     * @param token the Azure API access token
     */
    public AzureKeyVaultSigningService(String vault, String token) {
        this.vault = vault;
        this.token = token;
    }

    @Override
    public String getName() {
        return "AzureKeyVault";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            Map<String, ?> response = get("/certificates");
            Object[] certificates = (Object[]) response.get("value");
            for (Object certificate : certificates) {
                String id = (String) ((Map) certificate).get("id");
                aliases.add(id.substring(id.lastIndexOf('/') + 1));
            }
        } catch (AzureException | IOException e) {
            throw new KeyStoreException("Unable to retrieve Azure Key Vault certificate aliases", e);
        }

        return aliases;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        try {
            Map<String, ?> response = get("/certificates/" + alias);
            String pem = (String) response.get("cer");

            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(pem)));
            return new Certificate[]{certificate};
        } catch (AzureException | IOException | CertificateException e) {
            throw new KeyStoreException("Unable to retrieve Azure Key Vault certificate '" + alias + "'", e);
        }
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException {
        try {
            Map<String, ?> response = get("/certificates/" + alias);
            String kid = (String) response.get("kid");
            Map policy = (Map) response.get("policy");
            Map keyprops = (Map) policy.get("key_props");
            String algorithm = (String) keyprops.get("kty");

            return new SigningServicePrivateKey(kid, algorithm);
        } catch (AzureException | IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch Azure Key Vault private key for the certificate '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        String alg = algorithmMapping.get(algorithm);
        if (alg == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + algorithm);
        }

        MessageDigest digest = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with"))).getMessageDigest();
        data = digest.digest(data);

        Map<String, String> request = new HashMap<>();
        request.put("alg", alg);
        request.put("value", Base64.getEncoder().encodeToString(data));

        try {
            Map<String, Object> args = new HashMap<>();
            args.put(JsonWriter.TYPE, "false");
            Map<String, ?> response = post(privateKey.getId() + "/sign", JsonWriter.objectToJson(request, args));
            String value = (String) response.get("value");

            return Base64.getUrlDecoder().decode(value);
        } catch (AzureException | IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private Map<String, ?> get(String resource) throws AzureException, IOException {
        return query("GET", resource, null);
    }

    private Map<String, ?> post(String resource, String body) throws AzureException, IOException {
        return query("POST", resource, body);
    }

    private Map<String, ?> query(String method, String resource, String body) throws AzureException, IOException {
        URL url = new URL((resource.startsWith("http") ? resource : "https://" + vault + ".vault.azure.net/" + resource) + "?api-version=7.2");
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
                throw new AzureException(JsonReader.jsonToMaps(error));
            } else {
                throw new IOException("HTTP Error " + responseCode);
            }
        }
    }
}
