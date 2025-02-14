/*
 * Copyright 2025 Emmanuel Bourg
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class SignPathSigningServiceTest {

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
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"))
                .thenRespond()
                .withStatus(500);

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        assertEquals("aliases", Arrays.asList("jsign/rsa-2048-2022", "jsign2/rsa-2048", "jsign/rsa-2048"), service.aliases());
        assertEquals("aliases", Arrays.asList("jsign/rsa-2048-2022", "jsign2/rsa-2048", "jsign/rsa-2048"), service.aliases()); // test the cache
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");
        Certificate[] chain = service.getCertificateChain("jsign/rsa-2048");
        assertNotNull("null chain", chain);
        assertEquals("length", 1, chain.length);
        assertEquals("subject", "CN=Jsign Code Signing Test Certificate 2024 (RSA)", ((X509Certificate) chain[0]).getSubjectDN().getName());
    }

    @Test
    public void testGetCertificateChainWithError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(403);

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("jsign/rsa-2048"));
        assertEquals("message", "Unable to retrieve the SignPath signing policies", e.getMessage());
    }

    @Test
    public void testGetCertificateChainWithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("jsign/rsa-4096"));
        assertEquals("message", "Unable to retrieve SignPath signing policy 'jsign/rsa-4096'", e.getMessage());
    }

    @Test
    public void testGetCertificateChainWithInvalidData() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies-invalid.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("jsign/rsa-2048"));
        assertEquals("cause", CertificateException.class.getSimpleName(), e.getCause().getClass().getSimpleName());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign/rsa-2048", null);
        assertNotNull("null key", privateKey);
        assertEquals("id", "jsign/rsa-2048", privateKey.getId());
        assertEquals("algorithm", "RSA", privateKey.getAlgorithm());
    }

    @Test
    public void testGetPrivateKeyithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("jsign/rsa-4096", null));
        assertEquals("message", "Unable to initialize the SignPath private key for the certificate 'jsign/rsa-4096'", e.getMessage());
    }

    @Test
    public void testGetPrivateKeyWithMissingType() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies-invalid.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("jsign/rsa-2048", null));
        assertEquals("message", "Unable to initialize the SignPath private key for the certificate 'jsign/rsa-2048'", e.getMessage());
    }

    @Test
    public void testGetPrivateKeyWithError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(403);

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("jsign/rsa-2048", null));
        assertEquals("message", "Unable to retrieve the SignPath signing policies", e.getMessage());
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/organization/SigningRequests")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-request.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign/rsa-2048", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 256, signature.length);
    }

    @Test
    public void testSignWithInvalidAlgorithm() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/organization/Cryptoki/MySigningPolicies")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signpath-signing-policies.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/organization/SigningRequests")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/signpath-invalid-hash-algorithm-error.json"));

        SigningService service = new SignPathSigningService("http://localhost:" + port(), "organization", "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign/rsa-2048", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "400 - One or more validation errors occurred. - {\"\":[\"The hash algorithm does not match the given hash.\"]}", e.getCause().getMessage());
    }
}
