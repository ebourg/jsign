/**
 * Copyright 2025 Ivan Wallis
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
import java.security.Key;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;

import net.jsign.DigestAlgorithm;

/**
 * Signing service using the Venafi CodeSign Protect REST Service API.
 *
 * @since 7.0
 */
public class VenafiSigningService implements SigningService {

    /** Cache of certificates indexed by alias */
    private final Map<String, Map<String, ?>> certificates = new LinkedHashMap<>();

    /** The API endpoint of the Venafi CodeSign Protect */
    private final String endpoint;

    private final RESTClient client;

    /** The credentials to authenticate with the service */
    private final VenafiCredentials credentials;

     /** The name of the Venafi CodeSign Protect certificate KeyId */
     private String KeyId;

    /** Mapping between Java and Venafi CodeSign Protect signing algorithms */
    private final Map<String, Integer> algorithmMapping = new HashMap<>();
    {
        algorithmMapping.put("SHA256withRSA", 64);
        algorithmMapping.put("SHA384withRSA", 65);
        algorithmMapping.put("SHA512withRSA", 66);
        algorithmMapping.put("SHA256withECDSA", 4164);
        algorithmMapping.put("SHA384withECDSA", 4165);
        algorithmMapping.put("SHA512withECDSA", 4166);
    }

    /* Map ASN.1 DER prefix structures to MessageDigest Algorithm */

    private final byte[] getHashPrefix(Integer mechanism) {
        switch (mechanism) {
            case 64: case 4164:
                return new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}; // SHA256
            case 65: case 4165:
                return new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}; // SHA384
            case 66: case 4166:
                return new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}; // SHA512
            default: 
                return new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}; // SHA256
        }
    }


    /**
     * Creates a new Venafi CodeSign Protect service.
     *
     * @param endpoint         the Venafi API endpoint (for example <tt>https://demo.venafitpp.local/vedhsm/api/sign/</tt>)
     * @param credentials      the Venafi credentials
     */
    public VenafiSigningService(String endpoint, VenafiCredentials credentials) throws IOException {
        if (!endpoint.startsWith("http")) {
            endpoint = "https://" + endpoint;
        }
        this.endpoint = endpoint;
        this.credentials = credentials;
        String token = credentials.getSessionToken(endpoint);
        this.client = new RESTClient(endpoint)
            .authentication(conn -> conn.setRequestProperty("Authorization", "Bearer " + token ))
            .errorHandler(response -> response.get("error") + ": " + response.get("error_description"));
                
    }

    @Override
    public String getName() {
        return "Venafi";
    }

    private void loadKeyStore(String alias) throws KeyStoreException {
        if (certificates.isEmpty()) {
            try {
                Map<String, Object> request = new LinkedHashMap<>();
                request.put("EnvironmentFilter", new Integer[] { 0});
                request.put("ObjectTypeFilter", new Integer[] { 1});
                request.put("IncludeChains", true);
                request.put("LabelFilter", new String[] { alias });
        
                Map<String, ?> response = client.post("/vedhsm/api/getobjects", JsonWriter.format(request));
                
                Object[] keys = (Object[]) response.get("Certificates");
                for (Object key : keys) {
                    String name = (String) ((Map) key).get("Label");
                    KeyId = (String) ((Map) key).get("KeyId");
                    certificates.put(name, (Map<String, ?>) key);
                }
            } catch (IOException e) {
                throw new KeyStoreException("Unable to retrieve the Venafi keystore with alias: " + alias, e);
            }
        }
    }

    @Override
    public List<String> aliases() throws KeyStoreException {
        return new ArrayList<>(certificates.keySet());
    }

    @Override
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {

        try {
            loadKeyStore(alias);

            Map<String, ?> key = certificates.get(alias);
            if (key == null) {
                throw new KeyStoreException("Unable to retrieve Venafi certificate '" + alias + "'.  Verify that the Project/Environment is a valid Certificate environment type.");
            }

            String pem = (String) key.get("Value");
            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(pem)));

            return new Certificate[]{certificate};
        }  catch (CertificateException e) {
            throw new KeyStoreException("Unable to retrieve Venafi certificate '" + alias + "'.  Verify that the Project/Environment is a valid Certificate environment type.", e);
        }

    }

    @Override
    public SigningServicePrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException {
        try {
            Certificate[] chain = getCertificateChain(alias);
            String algorithm = chain[0].getPublicKey().getAlgorithm();
            System.out.println("algorithm: " + algorithm);
            return new SigningServicePrivateKey(alias, algorithm, this);
        } catch (KeyStoreException e) {
            throw (UnrecoverableKeyException) new UnrecoverableKeyException().initCause(e);
        }

    }

    public byte[] encodeASN1(byte[] sigBytes) throws IOException {

        // Split the sigbytes into r and s components
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sigBytes, 0, sigBytes.length / 2));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sigBytes, sigBytes.length / 2, sigBytes.length));

        // Create an ASN1 sequence containing r and s
        DLSequence components = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(r),
            new ASN1Integer(s)
        });

        // Marshal the components to ASN1 encoding
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(byteArrayOutputStream);
        asn1OutputStream.writeObject(components);
        asn1OutputStream.close();

        return byteArrayOutputStream.toByteArray();
    }

    @Override
    public byte[] sign(SigningServicePrivateKey privateKey, String algorithm, byte[] data) throws GeneralSecurityException {
        //System.out.println(algorithm);
        Integer clientMechanism = algorithmMapping.get(algorithm);
        if (clientMechanism == null) {
            throw new InvalidAlgorithmParameterException("Unsupported signing algorithm: " + clientMechanism);
        }

        try {
            DigestAlgorithm digestAlgorithm = DigestAlgorithm.getDefault();
            ByteArrayOutputStream out = new ByteArrayOutputStream();

                byte[] rsaPrefix = getHashPrefix(clientMechanism);
                out.write(rsaPrefix);
           
            data = digestAlgorithm.getMessageDigest().digest(data);
            out.write(data);
            byte[] arr_combined = out.toByteArray();

            Map<String, Object> request = new HashMap<>();

            Map<String, String> clientInfo = new HashMap<>();
            clientInfo.put("ClientLibraryName", "jsign");
            clientInfo.put("ClientLibraryVersion", "7.0.0");

            Map<String, String> processInfo = new HashMap<>();
            clientInfo.put("Executable", "jsign");

            request.put("ClientInfo", clientInfo);
            request.put("ProcessInfo", processInfo); 
            request.put("KeyId", KeyId);
            request.put("Data", Base64.getEncoder().encodeToString(arr_combined));
            request.put("ClientMechanism", clientMechanism);
            switch (algorithm) {
                case "SHA256withRSA": case "SHA384withRSA": case "SHA512withRSA":
                    request.put("Mechanism", 1); // RSA 
                    break;
                case "SHA256withECDSA": case "SHA384withECDSA": case "SHA512withECDSA":
                    request.put("Mechanism", 4161); // ECDSA
                    break;
                default:
                    request.put("Mechanism", 1); // RSA
            }
           
            Map<String, ?> response = client.post("/vedhsm/api/sign", JsonWriter.format(request));
            String status = (String) response.get("Error");
            if (status != null) {
                throw new IOException("Signing operation failed: " + response.get("Error"));
            }    
            String signature = (String) response.get("ResultData");

            if (algorithm.equals("SHA256withECDSA") || algorithm.equals("SHA384withECDSA") || algorithm.equals("SHA512withECDSA")) {
                return encodeASN1(Base64.getDecoder().decode(signature));
            } else {
                return Base64.getDecoder().decode(signature);
            }

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
