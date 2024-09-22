/**
 * Copyright 2022 Emmanuel Bourg
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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;

import net.jsign.DigestAlgorithm;

import static java.nio.charset.StandardCharsets.*;

/**
 * Signing service using the AWS API.
 *
 * @since 5.0
 * @see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/">AWS Key Management Service API Reference</a>
 * @see <a href="https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html">Signing AWS API Requests</a>
 */
public class AmazonSigningService implements SigningService {

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    /** Cache of private keys indexed by id */
    private final Map<String, SigningServicePrivateKey> keys = new HashMap<>();

    private final RESTClient client;

    /** Mapping between Java and AWS signing algorithms */
    private final Map<String, String> algorithmMapping = new HashMap<>();
    {
        algorithmMapping.put("SHA256withRSA", "RSASSA_PKCS1_V1_5_SHA_256");
        algorithmMapping.put("SHA384withRSA", "RSASSA_PKCS1_V1_5_SHA_384");
        algorithmMapping.put("SHA512withRSA", "RSASSA_PKCS1_V1_5_SHA_512");
        algorithmMapping.put("SHA256withECDSA", "ECDSA_SHA_256");
        algorithmMapping.put("SHA384withECDSA", "ECDSA_SHA_384");
        algorithmMapping.put("SHA512withECDSA", "ECDSA_SHA_512");
        algorithmMapping.put("SHA256withRSA/PSS", "RSASSA_PSS_SHA_256");
        algorithmMapping.put("SHA384withRSA/PSS", "RSASSA_PSS_SHA_384");
        algorithmMapping.put("SHA512withRSA/PSS", "RSASSA_PSS_SHA_512");
    }

     /**
     * Generates the endpoint URL for the given AWS region.
     *
     * @param region the AWS region
     * @return the endpoint URL
     */
    public static String getEndpointUrl(String region) {
        String useFipsEndpoint = getenv("AWS_USE_FIPS_ENDPOINT");
        if (useFipsEndpoint != null && useFipsEndpoint.equalsIgnoreCase("true")) {
            return "https://kms-fips." + region + ".amazonaws.com";
        }
        
        return "https://kms." + region + ".amazonaws.com";
    }

    /**
     * Creates a new AWS signing service.
     *
     * @param region           the AWS region holding the keys (for example <tt>eu-west-3</tt>)
     * @param credentials      the AWS credentials provider
     * @param certificateStore provides the certificate chain for the keys
     * @since 6.0
     */
    public AmazonSigningService(String region, Supplier<AmazonCredentials> credentials, Function<String, Certificate[]> certificateStore) {
        this(credentials, certificateStore, getEndpointUrl(region));
    }

    /**
     * Creates a new AWS signing service.
     *
     * @param region           the AWS region holding the keys (for example <tt>eu-west-3</tt>)
     * @param credentials      the AWS credentials
     * @param certificateStore provides the certificate chain for the keys
     */
    public AmazonSigningService(String region, AmazonCredentials credentials, Function<String, Certificate[]> certificateStore) {
        this(region, () -> credentials, certificateStore);
    }

    AmazonSigningService(Supplier<AmazonCredentials> credentials, Function<String, Certificate[]> certificateStore, String endpoint) {
        this.certificateStore = certificateStore;
        this.client = new RESTClient(endpoint)
                .authentication((conn, data) -> sign(conn, credentials.get(), data, null))
                .errorHandler(response -> response.get("__type") + ": " + response.get("message"));
    }

    /**
     * Creates a new AWS signing service.
     *
     * @param region           the AWS region holding the keys (for example <tt>eu-west-3</tt>)
     * @param credentials      the AWS credentials: <tt>accessKey|secretKey|sessionToken</tt> (the session token is optional)
     * @param certificateStore provides the certificate chain for the keys
     */
    @Deprecated
    public AmazonSigningService(String region, String credentials, Function<String, Certificate[]> certificateStore) {
        this(region, AmazonCredentials.parse(credentials), certificateStore);
    }

    @Override
    public String getName() {
        return "AWS";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            // kms:ListKeys (https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html)
            Map<String, ?> response = query("TrentService.ListKeys", "{}");
            Object[] keys = (Object[]) response.get("Keys");
            for (Object key : keys) {
                aliases.add((String) ((Map) key).get("KeyId"));
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

        String algorithm;

        try {
            // kms:DescribeKey (https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html)
            Map<String, ?> response = query("TrentService.DescribeKey", "{\"KeyId\":\"" + normalizeKeyId(alias) + "\"}");
            Map<String, ?> keyMetadata = (Map<String, ?>) response.get("KeyMetadata");

            String keyUsage = (String) keyMetadata.get("KeyUsage");
            if (!"SIGN_VERIFY".equals(keyUsage)) {
                throw new UnrecoverableKeyException("The key '" + alias + "' is not a signing key");
            }

            String keyState = (String) keyMetadata.get("KeyState");
            if (!"Enabled".equals(keyState)) {
                throw new UnrecoverableKeyException("The key '" + alias + "' is not enabled (" + keyState + ")");
            }

            String keySpec = (String) keyMetadata.get("KeySpec");
            algorithm = keySpec.substring(0, keySpec.indexOf('_'));
            if ("ECC".equals(algorithm)) {
                algorithm = "EC";
            }
        } catch (IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch AWS key '" + alias + "'").initCause(e);
        }

        SigningServicePrivateKey key = new SigningServicePrivateKey(alias, algorithm, this);
        keys.put(alias, key);
        return key;
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        String alg = algorithmMapping.get(algorithm);
        if (alg == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + algorithm);
        }

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        // kms:Sign (https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
        Map<String, String> request = new HashMap<>();
        request.put("KeyId", normalizeKeyId(privateKey.getId()));
        request.put("MessageType", "DIGEST");
        request.put("Message", Base64.getEncoder().encodeToString(data));
        request.put("SigningAlgorithm", alg);

        try {
            Map<String, ?> response = query("TrentService.Sign", JsonWriter.format(request));
            String signature = (String) response.get("Signature");
            return Base64.getDecoder().decode(signature);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Sends a request to the AWS API.
     */
    private Map<String, ?> query(String target, String body) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Amz-Target", target);
        headers.put("Content-Type", "application/x-amz-json-1.1");
        return client.post("/", body, headers);
    }

    /**
     * Prefixes the key id with <tt>alias/</tt> if necessary.
     */
    private String normalizeKeyId(String keyId) {
        if (keyId.startsWith("arn:") || keyId.startsWith("alias/")) {
            return keyId;
        }

        if (!keyId.matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) {
            return "alias/" + keyId;
        } else {
            return keyId;
        }
    }

    /**
     * Signs the request
     *
     * @see <a href="https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html">Signature Version 4 signing process</a>
     */
    void sign(HttpURLConnection conn, AmazonCredentials credentials, byte[] content, Date date) {
        DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        DateFormat dateTimeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        if (date == null) {
            date = new Date();
        }

        // Extract the service name and the region from the endpoint
        URL endpoint = conn.getURL();
        Pattern hostnamePattern = Pattern.compile("^([^.]+)\\.([^.]+)\\.amazonaws\\.com$");
        String host = endpoint.getHost();
        Matcher matcher = hostnamePattern.matcher(host);
        String regionName = matcher.matches() ? matcher.group(2) : "us-east-1";
        String serviceName = "kms";

        String credentialScope = dateFormat.format(date) + "/" + regionName + "/" + serviceName + "/" + "aws4_request";

        conn.addRequestProperty("X-Amz-Date", dateTimeFormat.format(date));

        // Create the canonical request (https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html)
        Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(conn.getRequestProperties());
        headers.put("Host", Collections.singletonList(host));

        String canonicalRequest = conn.getRequestMethod() + "\n"
                + endpoint.getPath() + (endpoint.getPath().endsWith("/") ? "" : "/") + "\n"
                + /* canonical query string, not used for kms operations */ "\n"
                + canonicalHeaders(headers) + "\n"
                + signedHeaders(headers) + "\n"
                + sha256(content);

        // Create the string to sign (https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html)
        String stringToSign = "AWS4-HMAC-SHA256" + "\n"
                + dateTimeFormat.format(date) + "\n"
                + credentialScope + "\n"
                + sha256(canonicalRequest.getBytes(UTF_8));

        // Derive the signing key (https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html)
        byte[] key = ("AWS4" + credentials.getSecretKey()).getBytes(UTF_8);
        byte[] signingKey = hmac("aws4_request", hmac(serviceName, hmac(regionName, hmac(dateFormat.format(date), key))));

        // Compute the signature (https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html)
        byte[] signature = hmac(stringToSign, signingKey);

        conn.setRequestProperty("Authorization",
                "AWS4-HMAC-SHA256 Credential=" + credentials.getAccessKey() + "/" + credentialScope
                + ", SignedHeaders=" + signedHeaders(headers)
                + ", Signature=" + Hex.toHexString(signature).toLowerCase());

        if (credentials.getSessionToken() != null) {
            conn.setRequestProperty("X-Amz-Security-Token", credentials.getSessionToken());
        }
    }

    private String canonicalHeaders(Map<String, List<String>> headers) {
        return headers.entrySet().stream()
                .map(entry -> entry.getKey().toLowerCase() + ":" + String.join(",", entry.getValue()).replaceAll("\\s+", " "))
                .collect(Collectors.joining("\n")) + "\n";
    }

    private String signedHeaders(Map<String, List<String>> headers) {
        return headers.keySet().stream()
                .map(String::toLowerCase)
                .collect(Collectors.joining(";"));
    }

    private byte[] hmac(String data, byte[] key) {
        return hmac(data.getBytes(UTF_8), key);
    }

    private byte[] hmac(byte[] data, byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String sha256(byte[] data) {
        MessageDigest digest =  DigestAlgorithm.SHA256.getMessageDigest();
        digest.update(data);
        return Hex.toHexString(digest.digest()).toLowerCase();
    }

    static String getenv(String name) {
        return System.getenv(name);
    }
}
