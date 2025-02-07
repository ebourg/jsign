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

import java.io.FileReader;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

public class VenafiSigningServiceTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testGetAliases() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .havingParameterEqualTo("api_version", "1.0")
                .havingParameter("session_token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("java_keystore_rsa_key", "java_keystore_ecdsa_key"), aliases);
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .havingParameterEqualTo("api_version", "1.0")
                .havingParameter("session_token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        Certificate[] chain = service.getCertificateChain("java_keystore_rsa_key");
        assertNotNull("null chain", chain);
        assertEquals("length", 3, chain.length);
        assertEquals("subject 1", "CN=rsa_code_signer, OU=test, O=Garantir, L=San Diego, ST=CA, C=US", ((X509Certificate) chain[0]).getSubjectDN().getName());
        assertEquals("subject 2", "CN=intermediary_rsa_ca, OU=test, O=Garantir, L=San Diego, ST=CA, C=US", ((X509Certificate) chain[1]).getSubjectDN().getName());
        assertEquals("subject 3", "CN=root_rsa_ca, OU=test, O=Garantir, L=San Diego, ST=CA, C=US", ((X509Certificate) chain[2]).getSubjectDN().getName());
    }

    @Test
    public void testGetCertificateChainWithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .havingParameter("session_token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("jsign"));
        assertEquals("message", "Unable to retrieve Venafi certificate 'jsign'", e.getMessage());
    }

    @Test
    public void testGetCertificateChainWithError() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"keystore_request\", \"status\": \"FAILURE\", \"message\": \"Keystore not found\", \"sessionToken\": null}");

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("java_keystore_rsa_key"));
        assertEquals("message", "Unable to retrieve the Venafi keystore: Keystore not found", e.getMessage());
    }

    @Test
    public void testGetCertificateChainWithHTTPError() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(502)
                .withBody("Bad Gateway");

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("java_keystore_rsa_key"));
        assertEquals("message", "Unable to retrieve the Venafi keystore", e.getMessage());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));

        SigningServicePrivateKey key = service.getPrivateKey("java_keystore_rsa_key", null);
        assertNotNull("null key", key);
        assertEquals("id", "java_keystore_rsa_key", key.getId());
        assertEquals("algorithm", "RSA", key.getAlgorithm());
    }

    @Test
    public void testGetPrivateKeyWithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("jsign", null));
        assertEquals("message", "Unable to fetch Venafi private key for the certificate 'jsign'", e.getMessage());
    }

    @Test
    public void testSignWithPolling() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign")
                .havingParameterEqualTo("api_version", "1.0")
                .havingParameter("session_token")
                .havingParameter("data_to_sign")
                .havingParameterEqualTo("key_name", "java_keystore_rsa_key")
                .havingParameterEqualTo("signature_scheme", "SHA256withRSA")
                .havingParameter("request_id", nullValue())
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"IN_PROGRESS\", \"message\": \"Pending approvals\"}");
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign")
                .havingParameterEqualTo("api_version", "1.0")
                .havingParameter("session_token")
                .havingParameter("data_to_sign", nullValue())
                .havingParameter("key_name", nullValue())
                .havingParameter("signature_scheme", nullValue())
                .havingParameterEqualTo("request_id", "60")
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"IN_PROGRESS\", \"message\": \"Pending approvals\"}")
                .thenRespond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"IN_PROGRESS\", \"message\": \"Pending approvals\"}")
                .thenRespond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-sign.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("java_keystore_rsa_key", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 256, signature.length);
    }

    @Test
    public void testSignWithoutPolling() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-sign.json"))
                .thenRespond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"FAILED\", \"message\": \"Data to sign is missing\"}");

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("java_keystore_rsa_key", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 256, signature.length);
    }

    @Test
    public void testSignWithTimeout() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign")
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"IN_PROGRESS\", \"message\": \"Pending approvals\"}");

        VenafiSigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        service.setTimeout(5);
        SigningServicePrivateKey privateKey = service.getPrivateKey("java_keystore_rsa_key", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Signing operation 60 timed out", e.getMessage());
    }

    @Test
    public void testSignWithFailure() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign")
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"FAILURE\", \"message\": \"Internal server error\"}");

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("java_keystore_rsa_key", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Signing operation failed: Internal server error", e.getMessage());
    }

    @Test
    public void testSignWithPollingFailure() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/authenticate")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-authenticate.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keystore")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign")
                .respond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"IN_PROGRESS\", \"message\": \"Pending approvals\"}")
                .thenRespond()
                .withStatus(200)
                .withBody("{\"requestId\": \"60\", \"status\": \"FAILURE\", \"message\": \"Internal server error\"}");

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("java_keystore_rsa_key", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Signing operation 60 failed: Internal server error", e.getMessage());
    }
}
