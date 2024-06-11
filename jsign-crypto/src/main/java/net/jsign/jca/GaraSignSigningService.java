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
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Garantir Remote Signing REST Service API.
 *
 * @since 7.0
 */
public class GaraSignSigningService implements SigningService {

    /** Cache of certificates indexed by alias */
    private final Map<String, Map<String, ?>> certificates = new LinkedHashMap<>();

    /** The API endpoint of the Garantir Remote Signing service */
    private final String endpoint;

    private final RESTClient client;

    /** The credentials to authenticate with the service */
    private final GaraSignCredentials credentials;

    /** Timeout in seconds for the signing operation */
    private long timeout = 60 * 60; // one hour

    /**
     * Creates a new GaraSign signing service.
     *
     * @param endpoint         the GaraSign API endpoint (for example <tt>https://demo.garantir.io/CodeSigningRestService/</tt>)
     * @param credentials      the GaraSign credentials
     */
    public GaraSignSigningService(String endpoint, GaraSignCredentials credentials) {
        this.endpoint = endpoint != null ? endpoint : "https://garasign.com:8443/CodeSigningRestService/";
        this.credentials = credentials;
        this.client = new RESTClient(endpoint);
    }

    void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public String getName() {
        return "GaraSign";
    }

    private void loadKeyStore() throws KeyStoreException {
        if (certificates.isEmpty()) {
            try {
                Map<String, String> params = new LinkedHashMap<>();
                params.put("api_version", "1.0");
                params.put("session_token", credentials.getSessionToken(endpoint));

                Map<String, ?> response = client.post("/keystore", params);
                String status = (String) response.get("status");
                if (!"SUCCESS".equals(status)) {
                    throw new KeyStoreException("Unable to retrieve the GaraSign keystore: " + response.get("message"));
                }

                Object[] keys = (Object[]) response.get("keys");
                for (Object key : keys) {
                    String name = (String) ((Map) key).get("name");
                    certificates.put(name, (Map<String, ?>) key);
                }
            } catch (IOException e) {
                throw new KeyStoreException("Unable to retrieve the GaraSign keystore", e);
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

        Map<String, ?> key = certificates.get(alias);
        if (key == null) {
            throw new KeyStoreException("Unable to retrieve GaraSign certificate '" + alias + "'");
        }

        Object[] certChain = (Object[]) key.get("certChain");
        Certificate[] chain = new Certificate[certChain.length];

        for (int i = 0; i < certChain.length; i++) {
            byte[] data = decode((Object[]) certChain[i]);

            try {
                chain[i] = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(data));
            } catch (CertificateException e) {
                throw new KeyStoreException(e);
            }
        }

        return chain;
    }

    private String getAlgorithm(String alias) throws KeyStoreException {
        loadKeyStore();
        Map<String, ?> key = certificates.get(alias);
        if (key == null) {
            return null;
        }

        return (String) key.get("algorithm");
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            String algorithm = getAlgorithm(alias);
            if (algorithm == null) {
                throw new UnrecoverableKeyException("Unable to fetch GaraSign private key for the certificate '" + alias + "'");
            }
            return new SigningServicePrivateKey(alias, algorithm, this);
        } catch (KeyStoreException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException().initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        try {
            Map<String, String> params = new LinkedHashMap<>();
            params.put("api_version", "1.0");
            params.put("session_token", credentials.getSessionToken(endpoint));
            params.put("key_name", privateKey.getId());
            params.put("signature_scheme", algorithm);
            params.put("data_to_sign", Base64.getEncoder().encodeToString(data));

            Map<String, ?> response = client.post("/sign", params);

            String status = (String) response.get("status");
            if ("FAILURE".equals(status)) {
                throw new IOException("Signing operation failed: " + response.get("message"));
            }

            String requestId = (String) response.get("requestId");

            params.put("request_id", requestId);
            params.remove("key_name");
            params.remove("signature_scheme");
            params.remove("data_to_sign");

            String message = null;
            if ("IN_PROGRESS".equals(status)) {
                // poll until the operation is completed
                long startTime = System.currentTimeMillis();
                int i = 0;
                while (System.currentTimeMillis() - startTime < timeout * 1000) {
                    try {
                        Thread.sleep(Math.min(1000, 100 + 100 * i++));
                    } catch (InterruptedException e) {
                        break;
                    }
                    response = client.post("/sign", params);
                    status = (String) response.get("status");
                    if ("IN_PROGRESS".equals(status)) {
                        // display the message once if the operation is pending for more than 3 seconds
                        if (System.currentTimeMillis() - startTime > 3000 && response.get("message") != null && !response.get("message").equals(message)) {
                            message = (String) response.get("message");
                        }
                        continue;
                    }
                    if ("SUCCESS".equals(status)) {
                        break;
                    }

                    throw new IOException("Signing operation " + requestId + " failed: " + response.get("message"));
                }
            }

            if (!"SUCCESS".equals(response.get("status"))) {
                throw new IOException("Signing operation " + requestId + " timed out");
            }

            return decode((Object[]) response.get("signature"));

        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private byte[] decode(Object[] array) {
        byte[] data = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            data[i] = ((Number) array[i]).byteValue();
        }
        return data;
    }
}
