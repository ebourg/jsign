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
import static org.junit.Assert.*;

public class CodeSignSecureSigningServiceTest {

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
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts.json"));

        CodeSignSecureCredentials credentials = new CodeSignSecureCredentials("guest", "secret", null, null);
        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), credentials);
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("JSign-Test-2026"), aliases);
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .havingParameterEqualTo("key", "JSign-Test-2026")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts-detail.json"));

        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), new CodeSignSecureCredentials("guest", "secret", null));
        Certificate[] chain = service.getCertificateChain("JSign-Test-2026");
        assertNotNull("null chain", chain);
        assertEquals("length", 1, chain.length);
        assertEquals("subject 1", "CN=JSign-Test-2026, OU=EC, O=Encryption Consulting, L=Texas, ST=Dallas, C=US", ((X509Certificate) chain[0]).getSubjectDN().getName());
    }

    @Test
    public void testGetCertificateChainWithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .havingParameterEqualTo("key", "JSign-Test-2027")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts-detail-error.json"));

        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), new CodeSignSecureCredentials("guest", "secret", null));

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("JSign-Test-2027"));
        assertEquals("message", "Unable to retrieve CodeSign Secure certificate 'JSign-Test-2027'", e.getMessage());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .havingParameterEqualTo("key", "JSign-Test-2026")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts-detail.json"));

        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), new CodeSignSecureCredentials("guest", "secret", null));

        SigningServicePrivateKey key = service.getPrivateKey("JSign-Test-2026", null);
        assertNotNull("null key", key);
        assertEquals("id", "JSign-Test-2026", key.getId());
        assertEquals("algorithm", "RSA", key.getAlgorithm());
    }

    @Test
    public void testGetPrivateKeyWithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .havingParameterEqualTo("key", "JSign-Test-2027")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts-detail-error.json"));

        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), new CodeSignSecureCredentials("guest", "secret", null));

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("JSign-Test-2027", null));
        assertEquals("message", "Unable to fetch CodeSign Secure key 'JSign-Test-2027'", e.getMessage());
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .havingParameterEqualTo("key", "JSign-Test-2026")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts-detail.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/signing/sign/")
                .havingBodyEqualTo("{\"certificate_name\":\"JSign-Test-2026\",\"hash\":\"185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969\"}")
                .respond()
                .withStatus(200)
                .withContentType("text/html; charset=utf-8")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-sign.txt"));

        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), new CodeSignSecureCredentials("guest", "secret", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("JSign-Test-2026", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 384, signature.length);
    }

    @Test
    public void testSignWithFailure() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/auth/GetLoginToken/")
                .havingHeaderEqualTo("Accept", "*/*")
                .havingBodyEqualTo("{\"user\":\"guest\",\"code\":\"secret\",\"identityType\":1}")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-logintoken.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/api/certificate_manage/activecerts/")
                .havingParameterEqualTo("key", "JSign-Test-2026")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-activecerts-detail.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/api/signing/sign/")
                .havingBodyEqualTo("{\"certificate_name\":\"JSign-Test-2026\",\"hash\":\"185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969\"}")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/codesignsecure-sign-error.json"));

        SigningService service = new CodeSignSecureSigningService("http://localhost:" + port(), new CodeSignSecureCredentials("guest", "secret", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("JSign-Test-2026", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Certificate key alias is not found", e.getMessage());
    }
}
