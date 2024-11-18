/**
 * Copyright 2024 Björn Kautler
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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.jsign.DigestAlgorithm;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Signing service using the Keyfactor SignServer REST API.
 *
 * @since 7.0
 */
public class SignServerSigningService implements SigningService {

    /** Cache of certificates indexed by alias (worker id or name) */
    private final Map<String, Certificate[]> certificates = new HashMap<>();

    private final RESTClient client;

    /**
     * Creates a new SignServer signing service.
     *
     * @param endpoint         the SignServer API endpoint (for example <tt>https://example.com/signserver</tt>)
     * @param credentials      the SignServer credentials
     */
    public SignServerSigningService(String endpoint, SignServerCredentials credentials) {
        this.client = new RESTClient(endpoint)
                .authentication(conn -> {
                    if (conn instanceof HttpsURLConnection && credentials.keystore != null) {
                        try {
                            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                            kmf.init(credentials.keystore.getKeyStore(), ((KeyStore.PasswordProtection) credentials.keystore.getProtectionParameter("")).getPassword());

                            SSLContext context = SSLContext.getInstance("TLS");
                            context.init(kmf.getKeyManagers(), null, new SecureRandom());
                            ((HttpsURLConnection) conn).setSSLSocketFactory(context.getSocketFactory());
                        } catch (GeneralSecurityException e) {
                            throw new RuntimeException("Unable to load the SignServer client certificate", e);
                        }
                    }

                    if (credentials.username != null) {
                        String httpCredentials = credentials.username + ":" + (credentials.password == null ? "" : credentials.password);
                        conn.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString(httpCredentials.getBytes(UTF_8)));
                    }
                })
                .errorHandler(response -> (String) response.get("error"));
    }

    @Override
    public String getName() {
        return "SignServer";
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        return Collections.emptyList();
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        if (!certificates.containsKey(alias)) {
            try {
                Map<String, Object> request = new HashMap<>();
                request.put("data", "");
                Map<String, String> metadata = new HashMap<>();
                metadata.put("USING_CLIENTSUPPLIED_HASH", "false");
                request.put("metaData", metadata);

                Map<String, ?> response = client.post("/rest/v1/workers/" + alias + "/process", JsonWriter.format(request));
                String encodedCertificate = response.get("signerCertificate").toString();
                byte[] certificateBytes = Base64.getDecoder().decode(encodedCertificate);
                Certificate certificate = CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(certificateBytes));
                certificates.put(alias, new Certificate[]{certificate});
            } catch (Exception e) {
                throw new KeyStoreException("Unable to retrieve the certificate chain '" + alias + "'", e);
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
            throw (UnrecoverableKeyException) new UnrecoverableKeyException().initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        Map<String, Object> request = new HashMap<>();
        request.put("data", Base64.getEncoder().encodeToString(data));
        request.put("encoding", "BASE64");
        Map<String, String> metadata = new HashMap<>();
        metadata.put("USING_CLIENTSUPPLIED_HASH", "false");
        request.put("metaData", metadata);

        try {
            Map<String, ?> response = client.post("/rest/v1/workers/" + privateKey.getId() + "/process", JsonWriter.format(request));
            return Base64.getDecoder().decode((String) response.get("data"));
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
