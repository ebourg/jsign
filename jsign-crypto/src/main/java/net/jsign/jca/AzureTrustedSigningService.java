/**
 * Copyright 2024 Emmanuel Bourg
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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.cedarsoftware.util.io.JsonWriter;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Azure Trusted Signing API.
 *
 * @since 6.1
 */
public class AzureTrustedSigningService implements SigningService {

    /** Cache of certificate chains indexed by alias */
    private final Map<String, Certificate[]> certificates = new HashMap<>();

    private final RESTClient client;

    /** Timeout in seconds for the signing operation */
    private long timeout = 60;

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

    public AzureTrustedSigningService(String endpoint, String token) {
        if (!endpoint.startsWith("http")) {
            endpoint = "https://" + endpoint;
        }
        client = new RESTClient(endpoint)
                .authentication(conn -> conn.setRequestProperty("Authorization", "Bearer " + token))
                .errorHandler(response -> {
                    String errors = JsonWriter.objectToJson(response.get("errors"));
                    return response.get("status") + " - " + response.get("title") + ": " + errors;
                });
    }

    void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public String getName() {
        return "TrustedSigning";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        return new ArrayList<>();
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        if (!certificates.containsKey(alias)) {
            try {
                String account = alias.substring(0, alias.indexOf('/'));
                String profile = alias.substring(alias.indexOf('/') + 1);
                SignStatus status = sign(account, profile, "RS256", new byte[32]);
                certificates.put(alias, status.getCertificateChain().toArray(new Certificate[0]));
            } catch (Exception e) {
                throw new KeyStoreException("Unable to retrieve the certificate chain '" + alias + "'", e);
            }
        }

        return certificates.get(alias);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        return new SigningServicePrivateKey(alias, "RSA", this);
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        String alg = algorithmMapping.get(algorithm);
        if (alg == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + algorithm);
        }

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        String alias = privateKey.getId();
        String account = alias.substring(0, alias.indexOf('/'));
        String profile = alias.substring(alias.indexOf('/') + 1);
        try {
            SignStatus status = sign(account, profile, alg, data);
            return status.signature;
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private SignStatus sign(String account, String profile, String algorithm, byte[] data) throws IOException {
        Map<String, Object> request = new HashMap<>();
        request.put("signatureAlgorithm", algorithm);
        request.put("digest", Base64.getEncoder().encodeToString(data));

        Map<String, Object> args = new HashMap<>();
        args.put(JsonWriter.TYPE, "false");

        Map<String, ?> response = client.post("/codesigningaccounts/" + account + "/certificateprofiles/" + profile + "/sign?api-version=2022-06-15-preview", JsonWriter.objectToJson(request, args));

        String operationId = (String) response.get("operationId");

        // poll until the operation is completed
        long startTime = System.currentTimeMillis();
        int i = 0;
        while (System.currentTimeMillis() - startTime < timeout * 1000) {
            try {
                Thread.sleep(Math.min(1000, 50 + 10 * i++));
            } catch (InterruptedException e) {
                break;
            }
            response = client.get("/codesigningaccounts/" + account + "/certificateprofiles/" + profile + "/sign/" + operationId + "?api-version=2022-06-15-preview");
            String status = (String) response.get("status");
            if ("InProgress".equals(status)) {
                continue;
            }
            if ("Succeeded".equals(status)) {
                break;
            }

            throw new IOException("Signing operation " + operationId + " failed: " + status);
        }

        if (!"Succeeded".equals(response.get("status"))) {
            throw new IOException("Signing operation " + operationId + " timed out");
        }

        SignStatus status = new SignStatus();
        status.signature = Base64.getDecoder().decode((String) response.get("signature"));
        status.signingCertificate = new String(Base64.getDecoder().decode((String) response.get("signingCertificate")));

        return status;
    }

    private static class SignStatus {
        public byte[] signature;
        public String signingCertificate;

        public Collection<? extends Certificate> getCertificateChain() throws CertificateException {
            byte[] cerbin = Base64.getMimeDecoder().decode(signingCertificate);

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return certificateFactory.generateCertificates(new ByteArrayInputStream(cerbin));
        }
    }
}
