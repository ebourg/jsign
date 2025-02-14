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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Oracle Cloud API.
 * 
 * @since 7.0
 */
public class OracleCloudSigningService implements SigningService {

    /** Source for the certificates */
    private final Function<String, Certificate[]> certificateStore;

    /** The credentials */
    private final OracleCloudCredentials credentials;

    /** Mapping between Java and OCI signing algorithms */
    private final Map<String, String> algorithmMapping = new HashMap<>();
    {
        algorithmMapping.put("SHA256withRSA", "SHA_256_RSA_PKCS1_V1_5");
        algorithmMapping.put("SHA384withRSA", "SHA_384_RSA_PKCS1_V1_5");
        algorithmMapping.put("SHA512withRSA", "SHA_512_RSA_PKCS1_V1_5");
        algorithmMapping.put("SHA256withECDSA", "ECDSA_SHA_256");
        algorithmMapping.put("SHA384withECDSA", "ECDSA_SHA_384");
        algorithmMapping.put("SHA512withECDSA", "ECDSA_SHA_512");
        algorithmMapping.put("SHA256withRSA/PSS", "SHA_256_RSA_PKCS_PSS");
        algorithmMapping.put("SHA384withRSA/PSS", "SHA_394_RSA_PKCS_PSS");
        algorithmMapping.put("SHA512withRSA/PSS", "SHA_512_RSA_PKCS_PSS");
    }

    /**
     * Creates a new Oracle Cloud signing service.
     *
     * @param credentials      the Oracle Cloud credentials (user, tenancy, region, private key)
     * @param certificateStore provides the certificate chain for the keys
     */
    public OracleCloudSigningService(OracleCloudCredentials credentials, Function<String, Certificate[]> certificateStore) {
        this.credentials = credentials;
        this.certificateStore = certificateStore;
    }

    @Override
    public String getName() {
        return "OracleCloud";
    }

    String getVaultEndpoint() {
        return "https://kms." + credentials.getRegion() + ".oraclecloud.com";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            // VaultSummary/ListVaults (https://docs.oracle.com/en-us/iaas/api/#/en/key/release/VaultSummary/ListVaults)
            RESTClient kmsClient = new RESTClient(getVaultEndpoint()).authentication(this::sign).errorHandler(this::error);
            Map<String, ?> result = kmsClient.get("/20180608/vaults?compartmentId=" + credentials.getTenancy());
            Object[] vaults = (Object[]) result.get("result");
            for (Object v : vaults) {
                Map<String, ?> vault = (Map<String, ?>) v;
                if ("ACTIVE".equals(vault.get("lifecycleState"))) {
                    String endpoint = (String) vault.get("managementEndpoint");
                    RESTClient managementClient = new RESTClient(endpoint).authentication(this::sign).errorHandler(this::error);

                    // KeySummary/ListKeys (https://docs.oracle.com/en-us/iaas/api/#/en/key/release/KeySummary/ListKeys)
                    result = managementClient.get("/20180608/keys?compartmentId=" + credentials.getTenancy());
                    Object[] keys = (Object[]) result.get("result");
                    for (Object k : keys) {
                        Map<String, ?> key = (Map<String, ?>) k;
                        if ("ENABLED".equals(key.get("lifecycleState")) && !"EXTERNAL".equals(key.get("protectionMode"))) {
                            aliases.add((String) key.get("id"));
                        }
                    }
                }
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
        Certificate[] chain = getCertificateChain(alias);
        String algorithm = chain[0].getPublicKey().getAlgorithm();

        return new SigningServicePrivateKey(alias, algorithm, this);
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        String alg = algorithmMapping.get(algorithm);
        if (alg == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + algorithm);
        }

        // SignedData/Sign (https://docs.oracle.com/en-us/iaas/api/#/en/key/release/SignedData/Sign)
        Map<String, String> request = new HashMap<>();
        request.put("keyId", privateKey.getId());
        request.put("messageType", "RAW");
        request.put("message", Base64.getEncoder().encodeToString(data));
        request.put("signingAlgorithm", alg);

        try {
            RESTClient client = new RESTClient(getKeyEndpoint(privateKey.getId())).authentication(this::sign).errorHandler(this::error);
            Map<String, ?> response = client.post("/20180608/sign", JsonWriter.format(request));
            String signature = (String) response.get("signature");
            return Base64.getDecoder().decode(signature);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    String getKeyEndpoint(String keyId) {
        // extract the vault from the key id
        Pattern pattern = Pattern.compile("ocid1\\.key\\.oc1\\.([^.]*)\\.([^.]*)\\..*");
        Matcher matcher = pattern.matcher(keyId);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid key id: " + keyId);
        }
        String region = matcher.group(1);
        String vaultId = matcher.group(2);

        String hostname = vaultId + "-crypto.kms." + region + ".oci.oraclecloud.com";
        if (isUnknownHost(hostname)) {
            hostname = vaultId + "-crypto.kms." + region + ".oraclecloud.com";
        }

        return "https://" + hostname;
    }

    boolean isUnknownHost(String hostname) {
        try {
            InetAddress.getByName(hostname);
            return false;
        } catch (UnknownHostException uhe) {
            return true;
        }
    }

    /**
     * Signs the request
     *
     * @see <a href="https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm">Request signatures</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-08">Signing HTTP Messages draft-cavage-http-signatures-08</a>
     */
    private void sign(HttpURLConnection conn, byte[] data) {
        StringBuilder signedHeaders = new StringBuilder();
        StringBuilder stringToSign = new StringBuilder();

        // date
        DateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        String date = dateFormat.format(new Date());
        conn.setRequestProperty("Date", date);
        addSignedHeader(signedHeaders, stringToSign, "date", date);

        // request target
        String query = conn.getURL().getPath() + (conn.getURL().getQuery() != null ? "?" + conn.getURL().getQuery() : "");
        addSignedHeader(signedHeaders, stringToSign, "(request-target)", conn.getRequestMethod().toLowerCase() + " " + query);

        // host
        addSignedHeader(signedHeaders, stringToSign, "host", conn.getURL().getHost());

        if (data != null) {
            // content length
            int contentLength = data.length;
            conn.setRequestProperty("Content-Length", String.valueOf(contentLength));
            addSignedHeader(signedHeaders, stringToSign, "content-length", String.valueOf(contentLength));

            // content type
            conn.setRequestProperty("Content-Type", "application/json");
            addSignedHeader(signedHeaders, stringToSign, "content-type", "application/json");

            // content sha256
            String digest = Base64.getEncoder().encodeToString(DigestAlgorithm.SHA256.getMessageDigest().digest(data));
            conn.setRequestProperty("x-content-sha256", digest);
            addSignedHeader(signedHeaders, stringToSign, "x-content-sha256", digest);
        }

        String signature = Base64.getEncoder().encodeToString(rsa256sign(credentials.getPrivateKey(), stringToSign.toString().trim()));
        String authorization = String.format("Signature headers=\"%s\",keyId=\"%s\",algorithm=\"rsa-sha256\",signature=\"%s\",version=\"1\"", signedHeaders.toString().trim(), credentials.getKeyId(), signature);
        conn.setRequestProperty("Authorization", authorization);
    }

    private void addSignedHeader(StringBuilder signedHeaders, StringBuilder stringToSign, String key, String value) {
        signedHeaders.append(key).append(" ");
        stringToSign.append(key).append(": ").append(value).append("\n");
    }

    private byte[] rsa256sign(PrivateKey privateKey, String message) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private String error(Map<String, ?> response) {
        return response.get("code") + ": " + response.get("message");
    }
}
