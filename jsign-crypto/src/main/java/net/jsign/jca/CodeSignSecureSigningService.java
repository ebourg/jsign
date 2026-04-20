/*
 * Copyright 2026 Emmanuel Bourg
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.util.encoders.Hex;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using Encryption Consulting CodeSign Secure REST API.
 *
 * @since 7.5
 */
public class CodeSignSecureSigningService implements SigningService {

    /** Cache of certificate chains indexed by alias */
    private final Map<String, Certificate[]> certificates = new HashMap<>();

    /** The API endpoint of the CodeSign Secure service */
    private final String endpoint;

    private final RESTClient client;

    /**
     * Creates a new EC CodeSign Secure signing service.
     *
     * @param endpoint         the CodeSign Secure API endpoint, defaults to <tt>https://codesignsecure.encryptionconsulting.com</tt> if null
     * @param credentials      the CodeSign Secure credentials
     */
    public CodeSignSecureSigningService(String endpoint, CodeSignSecureCredentials credentials) {
        this.endpoint = endpoint != null ? endpoint : "https://codesignsecure.encryptionconsulting.com";
        this.client = new RESTClient(this.endpoint)
                .authentication(conn -> {
                    try {
                        conn.setRequestProperty("Authorization", "Bearer " + credentials.getToken(CodeSignSecureSigningService.this.endpoint));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    if (conn instanceof HttpsURLConnection) {
                        try {
                            if (credentials.getSSLContext() != null) {
                                ((HttpsURLConnection) conn).setSSLSocketFactory(credentials.getSSLContext().getSocketFactory());
                            }
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException("Unable to load the CodeSign Secure client certificate", e);
                        }
                    }
                })
                .errorHandler(response -> (String) response.get("message"));
    }

    @Override
    public String getName() {
        return "CodeSignSecure";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        loadKeyStore();
        return new ArrayList<>(certificates.keySet());
    }

    private void loadKeyStore() throws KeyStoreException {
        if (certificates.isEmpty()) {
            try {
                Map<String, ?> response = client.get("/api/certificate_manage/activecerts/");
                Object[] keys = (Object[]) response.get("active_keys");
                for (Object key : keys) {
                    certificates.put(key.toString(), new Certificate[0]);
                }
            } catch (IOException e) {
                throw new KeyStoreException("Unable to retrieve CodeSign Secure keys", e);
            }
        }
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        Certificate[] chain = certificates.get(alias);
        if (chain == null || chain.length == 0) {
            try {
                Map<String, ?> response = client.get("/api/certificate_manage/activecerts/?key=" + alias);
                byte[] crt = Base64.getMimeDecoder().decode(response.get("message").toString());
                Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(crt));
                certificates.put(alias, new Certificate[]{certificate});
            } catch (IOException | CertificateException e) {
                throw new KeyStoreException("Unable to retrieve CodeSign Secure certificate '" + alias + "'", e);
            }
        }

        return certificates.get(alias);
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            String algorithm = getCertificateChain(alias)[0].getPublicKey().getAlgorithm();
            return new SigningServicePrivateKey(alias, algorithm, this);
        } catch (KeyStoreException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch CodeSign Secure key '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        Map<String, Object> request = new HashMap<>();
        request.put("certificate_name", privateKey.getId());
        request.put("hash", Hex.toHexString(data));

        try {
            Map<String, ?> response = client.post("/api/signing/sign/", JsonWriter.format(request));
            return Hex.decode((String) response.get("result"));
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
