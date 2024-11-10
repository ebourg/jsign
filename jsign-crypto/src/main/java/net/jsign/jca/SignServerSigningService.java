/*
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

import net.jsign.DigestAlgorithm;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;
import static java.util.Objects.requireNonNull;

/**
 * Signing service using the SignServer REST interface.
 *
 * @since 7.0
 */
public class SignServerSigningService implements SigningService {
    /** Cache of certificates indexed by id or alias */
    private final Map<String, Certificate[]> certificates = new HashMap<>();

    private final RESTClient client;

    /**
     * Creates a new SignServer signing service.
     *
     * @param endpoint         the SignServer API endpoint (for example <tt>https://signserver.company.com/signserver/</tt>)
     * @param credentials      the SignServer credentials
     */
    public SignServerSigningService(String endpoint, SignServerCredentials credentials) {
        this.client = new RESTClient(
                requireNonNull(endpoint, "You need to provide the SignServer endpoint URL as keystore parameter")
                        + (endpoint.endsWith("/") ? "" : "/"))
                .authentication(credentials::addAuthentication)
                .errorHandler(response -> response.get("error").toString());
    }

    @Override
    public String getName() {
        return "SignServer";
    }

    @Override
    public List<String> aliases() {
        return emptyList();
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        if (!certificates.containsKey(alias)) {
            try {
                Map<String, ?> response = client.post(getResourcePath(alias), "{\"data\":\"\"}");
                String encodedCertificate = response.get("signerCertificate").toString();
                byte[] certificateBytes = Base64.getDecoder().decode(encodedCertificate);
                Certificate certificate = CertificateFactory
                        .getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(certificateBytes));
                certificates.put(alias, new Certificate[]{certificate});
            } catch (IOException | CertificateException e) {
                throw new KeyStoreException(e);
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
        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        Map<String, Object> request = new HashMap<>();
        request.put("data", Base64.getEncoder().encodeToString(data));
        request.put("encoding", "BASE64");
        Map<String, Object> metaData = new HashMap<>();
        metaData.put("USING_CLIENTSUPPLIED_HASH", true);
        metaData.put("CLIENTSIDE_HASHDIGESTALGORITHM", digestAlgorithm.id);
        request.put("metaData", metaData);

        try {
            Map<String, ?> response = client.post(getResourcePath(privateKey.getId()), JsonWriter.format(request));
            String value = response.get("data").toString();
            return Base64.getDecoder().decode(value);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private String getResourcePath(String alias) {
        return "rest/v1/workers/" + alias + "/process";
    }
}
