/*
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
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Azure Artifact Signing API.
 *
 * @since 7.0
 */
public class AzureTrustedSigningService implements SigningService {

    private static final Logger log = Logger.getLogger(AzureTrustedSigningService.class.getName());

    /**
     * Default API version. It matches the version currently used in production and uses the legacy
     * REST layout (POST <code>.../sign</code> with a flat response body).
     */
    private static final String DEFAULT_API_VERSION = "2022-06-15-preview";

    /** Environment variable used to override the Azure Trusted Signing API version. */
    private static final String API_VERSION_ENV = "JSIGN_AZURE_API_VERSION";

    /**
     * First API version using the RPC-style layout (POST <code>.../certificateprofiles/{profile}:sign</code>,
     * operation tracked with the <code>operation-location</code> header, signature returned under
     * <code>result</code>). Any version greater than or equal to this value uses that layout.
     *
     * @see <a href="https://github.com/Azure/azure-rest-api-specs/blob/main/specification/trustedsigning/data-plane/TrustedSigning/preview/2023-06-15-preview/azure.developer.trustedsigning.json">2023-06-15-preview</a>
     * @see <a href="https://github.com/Azure/azure-rest-api-specs/blob/main/specification/artifactsigning/data-plane/ArtifactSigning/stable/2024-06-15/azure.developer.artifactsigning.json">2024-06-15 (stable)</a>
     */
    private static final String RPC_STYLE_MIN_VERSION = "2023-06-15";

    /** Cache of certificate chains indexed by alias */
    private final Map<String, Certificate[]> certificates = new HashMap<>();

    private final RESTClient client;

    /** API version used for the Azure Trusted Signing REST calls */
    private final String apiVersion;

    /** Whether the configured API version uses the RPC-style layout */
    private final boolean rpcStyle;

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
        this(endpoint, token, null);
    }

    /**
     * Creates an Azure Trusted Signing service using a specific API version.
     *
     * @param endpoint   the Azure Trusted Signing endpoint (for example <code>weu.codesigning.azure.net</code>)
     * @param token      the Azure API access token
     * @param apiVersion the API version to use. When <code>null</code> or blank the value of the
     *                   <code>JSIGN_AZURE_API_VERSION</code> environment variable is used if set,
     *                   otherwise the default version (<code>2022-06-15-preview</code>) is used.
     */
    public AzureTrustedSigningService(String endpoint, String token, String apiVersion) {
        if (!endpoint.startsWith("http")) {
            endpoint = "https://" + endpoint;
        }
        endpoint = endpoint.replaceFirst("/+$", "");

        this.apiVersion = resolveApiVersion(apiVersion);
        this.rpcStyle = isRpcStyle(this.apiVersion);
        log.fine("Azure Trusted Signing API version " + this.apiVersion + " (rpc-style=" + this.rpcStyle + ")");

        client = new RESTClient(endpoint)
                .authentication(conn -> conn.setRequestProperty("Authorization", "Bearer " + token))
                .errorHandler(response -> {
                    if (response.containsKey("errorDetail")) {
                        Map error = (Map) response.get("errorDetail");
                        return error.get("code") + " - " + error.get("message");
                    } else {
                        String errors = JsonWriter.format(response.get("errors"));
                        return response.get("status") + " - " + response.get("title") + ": " + errors;
                    }
                });
    }

    private static String resolveApiVersion(String apiVersion) {
        if (apiVersion != null && !apiVersion.trim().isEmpty()) {
            return apiVersion.trim();
        }
        String env = System.getenv(API_VERSION_ENV);
        if (env != null && !env.trim().isEmpty()) {
            return env.trim();
        }
        return DEFAULT_API_VERSION;
    }

    private static boolean isRpcStyle(String apiVersion) {
        // Versions 2023-06-15-preview and later use the RPC-style ":sign" layout.
        return apiVersion != null && apiVersion.compareTo(RPC_STYLE_MIN_VERSION) >= 0;
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
        return Collections.emptyList();
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

        String signVerb = rpcStyle ? ":sign" : "/sign";
        String signResource = "/codesigningaccounts/" + account + "/certificateprofiles/" + profile + signVerb + "?api-version=" + apiVersion;
        RESTClient.RESTResponse initialResponse = client.postResponse(signResource, JsonWriter.format(request));

        Map<String, ?> statusResponse = initialResponse.getBody();
        String operationLocation = initialResponse.getHeader("operation-location");
        String operationId = readOperationId(statusResponse);
        if (operationId == null) {
            operationId = extractOperationId(operationLocation);
        }
        if (operationId != null) {
            log.fine("Azure Trusted Signing operation started: " + operationId);
        }

        String status = statusResponse != null ? (String) statusResponse.get("status") : null;

        if (!isSucceeded(status)) {
            String statusResource = resolveStatusResource(account, profile, operationId, operationLocation);

            long startTime = System.currentTimeMillis();
            int i = 0;
            while (System.currentTimeMillis() - startTime < timeout * 1000) {
                try {
                    Thread.sleep(Math.min(1000, 50 + 10 * i++));
                } catch (InterruptedException e) {
                    break;
                }
                statusResponse = client.get(statusResource);
                status = statusResponse != null ? (String) statusResponse.get("status") : null;
                if (operationId == null) {
                    operationId = readOperationId(statusResponse);
                }
                if (isPending(status)) {
                    continue;
                }
                if (isSucceeded(status)) {
                    break;
                }

                throw new IOException("Signing operation " + describeOperation(operationId) + " failed: " + status);
            }

            if (!isSucceeded(status)) {
                throw new IOException("Signing operation " + describeOperation(operationId) + " timed out");
            }
        }

        SignStatus signStatus = buildSignStatus(statusResponse);
        if (signStatus == null) {
            throw new IOException("Signing operation " + describeOperation(operationId) + " returned no result");
        }

        return signStatus;
    }

    private SignStatus buildSignStatus(Map<String, ?> response) {
        if (response == null) {
            return null;
        }

        Map<String, ?> result = response;
        Object resultNode = response.get("result");
        if (resultNode instanceof Map) {
            result = (Map<String, ?>) resultNode;
        }

        Object signatureValue = result.get("signature");
        Object certificateValue = result.get("signingCertificate");
        if (!(signatureValue instanceof String) || !(certificateValue instanceof String)) {
            return null;
        }

        SignStatus status = new SignStatus();
        status.signature = Base64.getDecoder().decode((String) signatureValue);
        status.signingCertificate = new String(Base64.getDecoder().decode((String) certificateValue));
        return status;
    }

    private String resolveStatusResource(String account, String profile, String operationId, String operationLocation) throws IOException {
        if (operationLocation != null && !operationLocation.isEmpty()) {
            return ensureApiVersion(operationLocation.trim());
        }
        if (operationId != null && !operationId.isEmpty()) {
            return "/codesigningaccounts/" + account + "/certificateprofiles/" + profile + "/sign/" + operationId + "?api-version=" + apiVersion;
        }
        throw new IOException("Signing operation identifier not returned by Azure Trusted Signing");
    }

    private String ensureApiVersion(String resource) {
        if (resource == null || resource.isEmpty() || resource.contains("api-version=")) {
            return resource;
        }
        return resource + (resource.contains("?") ? "&" : "?") + "api-version=" + apiVersion;
    }

    private String extractOperationId(String operationLocation) {
        if (operationLocation == null || operationLocation.isEmpty()) {
            return null;
        }
        String value = operationLocation;
        int queryIndex = value.indexOf('?');
        if (queryIndex >= 0) {
            value = value.substring(0, queryIndex);
        }
        int slashIndex = value.lastIndexOf('/');
        if (slashIndex >= 0 && slashIndex < value.length() - 1) {
            return value.substring(slashIndex + 1);
        }
        return null;
    }

    private String readOperationId(Map<String, ?> response) {
        if (response == null) {
            return null;
        }
        Object value = response.get("operationId");
        if (value == null) {
            value = response.get("id");
        }
        return value instanceof String ? (String) value : null;
    }

    private boolean isPending(String status) {
        String normalized = normalizeStatus(status);
        return normalized == null || "INPROGRESS".equals(normalized) || "RUNNING".equals(normalized) || "NOTSTARTED".equals(normalized);
    }

    private boolean isSucceeded(String status) {
        return "SUCCEEDED".equals(normalizeStatus(status));
    }

    private String normalizeStatus(String status) {
        return status == null ? null : status.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
    }

    private String describeOperation(String operationId) {
        return operationId != null ? operationId : "unknown";
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
