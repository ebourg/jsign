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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.cedarsoftware.util.io.JsonWriter;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import net.jsign.DigestAlgorithm;

/**
 * SSL.com eSigner signing service.
 *
 * @see <a href="https://www.ssl.com/guide/integration-guide-testing-remote-signing-with-esigner-csc-api/">Integration Guide to Testing Remote Signing with eSigner CSC API</a>
 * @see <a href="https://www.ssl.com/guide/esigner-demo-credentials-and-certificates/">eSigner Demo Credentials and Certificates</a>
 * @see <a href="https://cloudsignatureconsortium.org/wp-content/uploads/2020/05/CSC_API_V0_0.1.7.9.pdf">CSC API specifications (version 0.1.7.9)</a>
 * @since 4.1
 */
public class ESignerSigningService implements SigningService {

    /** Cache of certificates indexed by alias */
    private final Map<String, Map<String, ?>> certificates = new HashMap<>();

    private final RESTClient client;

    public ESignerSigningService(String endpoint, String username, String password) throws IOException {
        this(endpoint, getAccessToken(endpoint.contains("-try.ssl.com") ? "https://oauth-sandbox.ssl.com" : "https://login.ssl.com",
                endpoint.contains("-try.ssl.com") ? "qOUeZCCzSqgA93acB3LYq6lBNjgZdiOxQc-KayC3UMw" : "kaXTRACNijSWsFdRKg_KAfD3fqrBlzMbWs6TwWHwAn8",
                username, password));
    }

    public ESignerSigningService(String endpoint, String accessToken) {
        client = new RESTClient(endpoint, conn -> conn.setRequestProperty("Authorization", "Bearer " + accessToken));
    }

    private static String getAccessToken(String endpoint, String clientId, String username, String password) throws IOException {
        Map<String, String> request = new LinkedHashMap<>();
        request.put("client_id", clientId);
        request.put("grant_type", "password");
        request.put("username", username);
        request.put("password", password);

        RESTClient client = new RESTClient(endpoint, null);
        Map<String, ?> response = client.post("/oauth2/token", JsonWriter.objectToJson(request));
        return (String) response.get("access_token");
    }

    @Override
    public String getName() {
        return "ESIGNER";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        try {
            Map<String, String> request = new HashMap<>();
            request.put("clientData", "EVCS");
            Map<String, ?> response = client.post("/csc/v0/credentials/list", JsonWriter.objectToJson(request));
            Object[] credentials = (Object[]) response.get("credentialIDs");
            return Stream.of(credentials).map(Object::toString).collect(Collectors.toList());
        } catch (IOException e) {
            throw new KeyStoreException("Unable to retrieve SSL.com certificate aliases", e);
        }
    }

    /**
     * Returns the certificate details
     *
     * @param alias the alias of the certificate
     */
    private Map<String, ?> getCertificateInfo(String alias) throws IOException {
        if (!certificates.containsKey(alias)) {
            Map<String, String> request = new HashMap<>();
            request.put("credentialID", alias);
            request.put("certificates", "chain");
            Map<String, ?> response = client.post("/csc/v0/credentials/info", JsonWriter.objectToJson(request));
            certificates.put(alias, (Map) response.get("cert"));
        }

        return certificates.get(alias);
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        try {
            Map<String, ?> cert = getCertificateInfo(alias);
            Object[] encodedChain = (Object[]) cert.get("certificates");

            List<Certificate> chain = new ArrayList<>();
            for (Object encodedCertificate : encodedChain) {
                chain.add(CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate.toString()))));
            }
            return chain.toArray(new Certificate[0]);
        } catch (IOException | CertificateException e) {
            throw new KeyStoreException("Unable to retrieve SSL.com certificate '" + alias + "'", e);
        }
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            Certificate[] chain = getCertificateChain(alias);
            String algorithm = chain[0].getPublicKey().getAlgorithm();
            SigningServicePrivateKey key = new SigningServicePrivateKey(alias, algorithm);
            if (password != null) {
                key.getProperties().put("totpsecret", new String(password));
            }
            return key;
        } catch (KeyStoreException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException().initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        MessageDigest digest = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with"))).getMessageDigest();
        data = digest.digest(data);
        String hash = Base64.getEncoder().encodeToString(data);

        Map<String, Object>  request = new LinkedHashMap<>();
        request.put("credentialID", privateKey.getId());
        request.put("SAD", getSignatureActivationData(privateKey, hash));
        request.put("hash", new String[] { hash });
        request.put("signAlgo", new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm).getAlgorithm().getId());

        Map<String, Object> args = new HashMap<>();
        args.put(JsonWriter.TYPE, "false");
        try {
            Map<String, ?> response = client.post("/csc/v0/signatures/signHash", JsonWriter.objectToJson(request, args));
            Object[] signatures = (Object[]) response.get("signatures");

            return Base64.getDecoder().decode(signatures[0].toString());
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private String getSignatureActivationData(SigningServicePrivateKey privateKey, String hash) throws GeneralSecurityException {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("credentialID", privateKey.getId());
        request.put("numSignatures", 1);
        request.put("hash", new String[] { hash });

        String totpsecret = (String) privateKey.getProperties().get("totpsecret");
        if (totpsecret != null) {
            request.put("OTP", generateOTP(totpsecret));
        }

        try {
            Map<String, Object> args = new HashMap<>();
            args.put(JsonWriter.TYPE, "false");
            Map<String, ?> response = client.post("/csc/v0/credentials/authorize", JsonWriter.objectToJson(request, args));
            return (String) response.get("SAD");
        } catch (IOException e) {
            throw new GeneralSecurityException("Couldn't get signing authorization for SSL.com certificate " + privateKey.getId(), e);
        }
    }

    private String generateOTP(String secret) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA1");

        byte[] counter = new byte[8];
        ByteBuffer.wrap(counter).putLong(System.currentTimeMillis() / 30000);

        mac.init(new SecretKeySpec(Base64.getDecoder().decode(secret), "RAW"));
        mac.update(counter);
        ByteBuffer hash = ByteBuffer.wrap(mac.doFinal());

        int offset = hash.get(hash.capacity() - 1) & 0x0F;
        long value = (hash.getInt(offset) & 0x7FFFFFFF) % 1000000;

        return String.format("%06d", value);
    }
}
