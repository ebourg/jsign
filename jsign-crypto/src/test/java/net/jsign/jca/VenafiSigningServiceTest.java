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
        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        List<String> aliases = service.aliases();

        assertEquals("aliases", Collections.emptyList(), aliases);
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/vedhsm/api/getobjects")
                .havingHeaderEqualTo("Authorization", "Bearer da49LbfHokLO+fKwFIneJg==")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        Certificate[] chain = service.getCertificateChain("project-test-cert");
        assertNotNull("null chain", chain);
        assertEquals("length", 1, chain.length);
        assertEquals("subject 1", "CN=test_signer, OU=test, O=Venafi, L=Salt Lake City, ST=UT, C=US", ((X509Certificate) chain[0]).getSubjectDN().getName());
    }

    @Test
    public void testGetCertificateChainWithInvalidAlias() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/vedhsm/api/getobjects")
                .havingHeaderEqualTo("Authorization", "Bearer da49LbfHokLO+fKwFIneJg==")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-keystore.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("jsign"));
        assertEquals("message", "Unable to retrieve Venafi certificate 'jsign'", e.getMessage());
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/vedhsm/api/sign")
                .havingHeaderEqualTo("Authorization", "Bearer da49LbfHokLO+fKwFIneJg==")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-sign.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("project-test-cert", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 256, signature.length);
    }

    @Test
    public void testSignWithFailure() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/vedhsm/api/sign")
                .havingHeaderEqualTo("Authorization", "Bearer da49LbfHokLO+fKwFIneJg==")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/venafi-sign-error.json"));

        SigningService service = new VenafiSigningService("http://localhost:" + port(), new VenafiCredentials("username", "password", null));
        SigningServicePrivateKey privateKey = service.getPrivateKey("project-test-cert", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Signing operation failed: Bad Request", e.getMessage());
    }
}
