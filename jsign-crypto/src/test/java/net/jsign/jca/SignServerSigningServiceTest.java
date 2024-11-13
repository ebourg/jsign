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

import java.io.FileReader;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class SignServerSigningServiceTest {

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
        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials("username", "password", null));
        List<String> aliases = service.aliases();

        assertEquals("aliases", Collections.emptyList(), aliases);
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/rest/v1/workers/default/process")
                .havingHeaderEqualTo("Authorization", "Basic dXNlcm5hbWU6")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signserver-plainworker-process.json"));

        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials("username", null, null));
        Certificate[] chain = service.getCertificateChain("default");
        assertNotNull("null chain", chain);
        assertEquals("length", 1, chain.length);
        assertEquals("subject", "CN=Jsign Test Certificate", ((X509Certificate) chain[0]).getSubjectDN().getName());
        assertSame("cached chain", chain, service.getCertificateChain("default"));
    }

    @Test
    public void testGetCertificateChainWithInvalidAlias() {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/rest/v1/workers/default/process")
                .havingHeaderEqualTo("Authorization", "Basic dXNlcm5hbWU6")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\": \"No such worker\"}");

        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials("username", null, null));

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("default"));
        assertEquals("message", "Unable to retrieve the certificate chain 'default'", e.getMessage());
        assertEquals("message", "No such worker", e.getCause().getMessage());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/rest/v1/workers/default/process")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signserver-plainworker-process.json"));

        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials(null, null, null));

        SigningServicePrivateKey key = service.getPrivateKey("default", null);
        assertNotNull("null key", key);
        assertEquals("id", "default", key.getId());
        assertEquals("algorithm", "RSA", key.getAlgorithm());
    }

    @Test
    public void testGetPrivateKeyWithInvalidAlias() {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/rest/v1/workers/default/process")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\": \"No such worker\"}");

        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials(null, null, null));

        assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("default", null));
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/rest/v1/workers/default/process")
                .havingHeaderEqualTo("Authorization", "Basic dXNlcm5hbWU6cGFzc3dvcmQ=")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signserver-plainworker-process.json"));

        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials("username", "password", null, null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("default", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 256, signature.length);
    }

    @Test
    public void testSignWithFailure() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/rest/v1/workers/default/process")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/signserver-plainworker-process.json"))
                .thenRespond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\": \"No such worker\"}");

        SigningService service = new SignServerSigningService("http://localhost:" + port(), new SignServerCredentials("username", "password", null));

        SigningServicePrivateKey privateKey = service.getPrivateKey("default", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: No such worker", e.getMessage());
    }
}
