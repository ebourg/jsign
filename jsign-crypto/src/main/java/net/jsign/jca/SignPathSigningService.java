/**
 * Copyright 2025 Emmanuel Bourg
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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the SignPath REST API.
 *
 * @since 7.1
 * @see <a href="https://about.signpath.io/documentation/crypto-providers/rest-api">SignPath REST API</a>
 */
public class SignPathSigningService implements SigningService {

    /** Cache of certificates indexed by alias */
    private final Map<String, Map<String, ?>> certificates = new HashMap<>();

    private final RESTClient client;

    /**
     * Create a new SignPath signing service.
     *
     * @param organizationId the organization ID
     * @param token          the API access token
     */
    public SignPathSigningService(String organizationId, String token) {
        this("https://app.signpath.io/API/v1", organizationId, token);
    }

    SignPathSigningService(String endpoint, String organizationId, String token) {
        this.client = new RESTClient(endpoint + "/" + organizationId)
                .authentication(conn -> conn.setRequestProperty("Authorization", "Bearer " + token))
                .errorHandler(response -> response.get("status") + " - " + response.get("title") + " - " + JsonWriter.format(response.get("errors")));
    }

    @Override
    public String getName() {
        return "SignPath";
    }

    private void loadKeyStore() throws KeyStoreException {
        if (certificates.isEmpty()) {
            try {
                Map<String, ?> response = client.get("/Cryptoki/MySigningPolicies");
                Object[] policies = (Object[]) response.get("signingPolicies");
                for (Object policy : policies) {
                    String alias = ((Map) policy).get("projectSlug") + "/" + ((Map) policy).get("signingPolicySlug");
                    certificates.put(alias, ((Map) policy));
                }
            } catch (IOException e) {
                throw new KeyStoreException("Unable to retrieve the SignPath signing policies", e);
            }
        }
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        loadKeyStore();
        return new ArrayList<>(certificates.keySet());
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        loadKeyStore();

        Map<String, ?> policy = certificates.get(alias);
        if (policy == null) {
            throw new KeyStoreException("Unable to retrieve SignPath signing policy '" + alias + "'");
        }

        byte[] certificateBytes = Base64.getDecoder().decode((String) policy.get("certificateBytes"));
        Certificate certificate;
        try {
            certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificateBytes));
        } catch (CertificateException e) {
            throw new KeyStoreException(e);
        }

        return new Certificate[] { certificate };
    }

    private String getAlgorithm(String alias) throws KeyStoreException {
        loadKeyStore();
        Map<String, ?> policy = certificates.get(alias);
        if (policy == null) {
            return null;
        }

        String keyType = (String) policy.get("keyType");

        return keyType != null ? keyType.toUpperCase() : null;
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            String algorithm = getAlgorithm(alias);
            if (algorithm == null) {
                throw new UnrecoverableKeyException("Unable to initialize the SignPath private key for the certificate '" + alias + "'");
            }
            return new SigningServicePrivateKey(alias, algorithm, this);
        } catch (KeyStoreException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException(e.getMessage()).initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        String[] slugs = privateKey.getId().split("/");
        String project = slugs[0];
        String signingPolicy = slugs[1];

        Map<String, String> artifact = new LinkedHashMap<>();
        artifact.put("SignatureAlgorithm", "RsaPkcs1");
        artifact.put("RsaHashAlgorithm", digestAlgorithm.oid.toString());
        artifact.put("Base64EncodedHash", Base64.getEncoder().encodeToString(data));

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("ProjectSlug", project);
        request.put("SigningPolicySlug", signingPolicy);
        request.put("IsFastSigningRequest", "true");
        request.put("Artifact", JsonWriter.format(artifact).getBytes(StandardCharsets.UTF_8));

        try {
            Map<String, ?> response = client.post("/SigningRequests", request, true);
            String signature = (String) response.get("Signature");

            return Base64.getDecoder().decode(signature);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
