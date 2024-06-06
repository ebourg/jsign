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
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
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

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Azure KeyVault API.
 *
 * @since 4.0
 * @see <a href="https://docs.microsoft.com/en-us/rest/api/keyvault/">Azure Key Vault REST API reference</a>
 */
public class AzureKeyVaultSigningService implements SigningService {

    /** Cache of certificates indexed by alias */
    private final Map<String, Map<String, ?>> certificates = new HashMap<>();

    private final RESTClient client;

    /**
     * Mapping between Java and Azure signing algorithms.
     * @see <a href="https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm">Key Vault API - JonWebKeySignatureAlgorithm</a>
     */
    private final Map<String, String> algorithmMapping = new HashMap<>();
    {
        algorithmMapping.put("SHA1withRSA", "RSNULL");
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

    /**
     * Creates a new Azure Key Vault signing service.
     *
     * @param vault the name of the key vault, either the short name (e.g. <tt>myvault</tt>),
     *              or the full URL (e.g. <tt>https://myvault.vault.azure.net</tt>).
     * @param token the Azure API access token
     */
    public AzureKeyVaultSigningService(String vault, String token) {
        if (!vault.startsWith("http")) {
            vault = "https://" + vault + ".vault.azure.net";
        }
        this.client = new RESTClient(vault)
                .authentication(conn -> conn.setRequestProperty("Authorization", "Bearer " + token))
                .errorHandler(response -> {
                    Map error = (Map) response.get("error");
                    return error.get("code") + ": " + error.get("message");
                });
    }

    @Override
    public String getName() {
        return "AzureKeyVault";
    }

    /**
     * Returns the certificate details
     *
     * @param alias the alias of the certificate
     */
    private Map<String, ?> getCertificateInfo(String alias) throws IOException {
        if (!certificates.containsKey(alias)) {
            Map<String, ?> response = client.get("/certificates/" + alias + "?api-version=7.2");
            certificates.put(alias, response);
        }

        return certificates.get(alias);
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        List<String> aliases = new ArrayList<>();

        try {
            Map<String, ?> response = client.get("/certificates?api-version=7.2");
            Object[] certificates = (Object[]) response.get("value");
            for (Object certificate : certificates) {
                String id = (String) ((Map) certificate).get("id");
                aliases.add(id.substring(id.lastIndexOf('/') + 1));
            }
        } catch (IOException e) {
            // return an empty list when called from the jarsigner JDK tool, because jarsigner fetches the aliases
            // even if unnecessary for signing and this requires extra permissions on the Azure account (see #219)
            if (!isCalledByJarSigner(e.getStackTrace())) {
                throw new KeyStoreException("Unable to retrieve Azure Key Vault certificate aliases", e);
            }
        }

        return aliases;
    }

    /**
     * Checks the stacktrace and tells if the calling class is the jarsigner tool.
     */
    private boolean isCalledByJarSigner(StackTraceElement[] trace) {
        for (StackTraceElement element : trace) {
            if (element.getClassName().contains("jarsigner")) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        try {
            Map<String, ?> response = getCertificateInfo(alias);
            String pem = (String) response.get("cer");

            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(pem)));
            return new Certificate[]{certificate};
        } catch (IOException | CertificateException e) {
            if (e.getMessage() != null && e.getMessage().contains("was not found in this key vault")) {
                return null;
            } else {
                throw new KeyStoreException("Unable to retrieve Azure Key Vault certificate '" + alias + "'", e);
            }
        }
    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            Map<String, ?> response = getCertificateInfo(alias);
            String kid = (String) response.get("kid");
            Map policy = (Map) response.get("policy");
            Map keyprops = (Map) policy.get("key_props");
            String algorithm = ((String) keyprops.get("kty")).replace("-HSM", "");

            return new SigningServicePrivateKey(kid, algorithm, this);
        } catch (IOException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException("Unable to fetch Azure Key Vault private key for the certificate '" + alias + "'").initCause(e);
        }
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        String alg = algorithmMapping.get(algorithm);
        if (alg == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + algorithm);
        }

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.of(algorithm.substring(0, algorithm.toLowerCase().indexOf("with")));
        data = digestAlgorithm.getMessageDigest().digest(data);

        if (alg.equals("RSNULL")) {
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
            DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, data);
            try {
                data = digestInfo.getEncoded("DER");
            } catch (IOException e) {
                throw new GeneralSecurityException(e);
            }
        }

        Map<String, String> request = new HashMap<>();
        request.put("alg", alg);
        request.put("value", Base64.getEncoder().encodeToString(data));

        try {
            Map<String, ?> response = client.post(privateKey.getId() + "/sign?api-version=7.2", JsonWriter.format(request));
            String value = (String) response.get("value");

            return Base64.getUrlDecoder().decode(value);
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }
}
