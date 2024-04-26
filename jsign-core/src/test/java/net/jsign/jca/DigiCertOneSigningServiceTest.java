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

import java.io.File;
import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.X509KeyManager;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class DigiCertOneSigningServiceTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    private SigningService getTestService() {
        File keystore = new File("target/test-classes/keystores/keystore.p12");
        X509KeyManager keyManager = (X509KeyManager) DigiCertOneSigningService.getKeyManager(keystore, "password");
        return new DigiCertOneSigningService("http://localhost:" + port(), "myapikey", keyManager);
    }

    @Test
    public void testGetAliases() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileInputStream("target/test-classes/services/digicertone-certificates.json"));

        SigningService service = getTestService();
        List<String> aliases = service.aliases();

        assertEquals("aliases", Collections.singletonList("jsign-2022-cert"), aliases);
    }

    @Test
    public void testGetAliasesWithError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .respond()
                .withStatus(500);

        SigningService service = getTestService();
        try {
            service.aliases();
            fail("Exception not thrown");
        } catch (KeyStoreException e) {
            assertEquals("message", "Unable to retrieve DigiCert ONE certificate aliases", e.getMessage());
        }
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileInputStream("target/test-classes/services/digicertone-certificates.json"));

        SigningService service = getTestService();
        Certificate[] chain = service.getCertificateChain("jsign-2022-cert");
        assertNotNull("null chain", chain);
        assertEquals("length", 3, chain.length);
        assertEquals("subject 1", "CN=Jsign Code Signing Test Certificate 2022 (RSA)", ((X509Certificate) chain[0]).getSubjectDN().getName());
        assertEquals("subject 2", "CN=Jsign Code Signing CA 2022", ((X509Certificate) chain[1]).getSubjectDN().getName());
        assertEquals("subject 3", "CN=Jsign Root Certificate Authority 2022", ((X509Certificate) chain[2]).getSubjectDN().getName());
    }

    @Test
    public void testGetCertificateChainWithInvalidAlias() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .havingQueryStringEqualTo("alias=jsign-1977-cert")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody("{\"total\":0,\"offset\":0,\"limit\":20,\"items\":[]}");

        SigningService service = getTestService();
        try {
            service.getCertificateChain("jsign-1977-cert");
            fail("Exception not thrown");
        } catch (KeyStoreException e) {
            assertEquals("message", "Unable to retrieve DigiCert ONE certificate 'jsign-1977-cert'", e.getMessage());
        }
    }

    @Test
    public void testGetCertificateChainWithError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .respond()
                .withStatus(500);

        SigningService service = getTestService();
        try {
            service.getCertificateChain("jsign-1995-cert");
            fail("Exception not thrown");
        } catch (KeyStoreException e) {
            assertEquals("message", "Unable to retrieve DigiCert ONE certificate 'jsign-1995-cert'", e.getMessage());
        }
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileInputStream("target/test-classes/services/digicertone-certificates.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1//keypairs/ea936a8f-446d-8bab-b782-c01e8612bf1e")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileInputStream("target/test-classes/services/digicertone-keypairs.json"));

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign-2022-cert");

        assertNotNull("null key", privateKey);
        assertEquals("id", "ea936a8f-446d-8bab-b782-c01e8612bf1e", privateKey.getId());
        assertEquals("algorithm", "RSA", privateKey.getAlgorithm());
        assertTrue("missing account info", privateKey.getProperties().containsKey("account"));
    }

    @Test
    public void testGetPrivateKeyWithError() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1/certificates")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileInputStream("target/test-classes/services/digicertone-certificates.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/signingmanager/api/v1//keypairs/ea936a8f-446d-8bab-b782-c01e8612bf1e")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\":{\"status\":\"invalid_input_field\",\"message\":\"Keypair not present for given keypairId ea936a8f-b782-446d-8bab-c01e8612bf1e. Please provide correct keypairId.\"}}");

        SigningService service = getTestService();
        try {
            service.getPrivateKey("jsign-2022-cert", null);
            fail("Exception not thrown");
        } catch (UnrecoverableKeyException e) {
            assertEquals("message", "Unable to fetch DigiCert ONE private key for the certificate 'jsign-2022-cert'", e.getMessage());
            assertEquals("root cause", "invalid_input_field: Keypair not present for given keypairId ea936a8f-b782-446d-8bab-c01e8612bf1e. Please provide correct keypairId.", e.getCause().getMessage());
        }
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/signingmanager/api/v1/keypairs/ea936a8f-446d-8bab-b782-c01e8612bf1e/sign")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileInputStream("target/test-classes/services/digicertone-sign.json"));

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = new SigningServicePrivateKey("ea936a8f-446d-8bab-b782-c01e8612bf1e", "RSA", service);
        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 384, signature.length);
    }

    @Test
    public void testSignWithInvalidKey() {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/signingmanager/api/v1/keypairs/ea936a8f-446d-8bab-b782-c01e8612bf1e/sign")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\":{\"status\":\"invalid_input_field\",\"message\":\"Keypair not present for given keypairId aea936a8f-b782-446d-8bab-c01e8612bf1e. Please provide correct keypairId.\"}}");

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = new SigningServicePrivateKey("ea936a8f-446d-8bab-b782-c01e8612bf1e", "RSA", service);
        try {
            service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());
            fail("Exception not thrown");
        } catch (GeneralSecurityException e) {
            assertEquals("message", "java.io.IOException: invalid_input_field: Keypair not present for given keypairId aea936a8f-b782-446d-8bab-c01e8612bf1e. Please provide correct keypairId.", e.getMessage());
        }
    }
}
