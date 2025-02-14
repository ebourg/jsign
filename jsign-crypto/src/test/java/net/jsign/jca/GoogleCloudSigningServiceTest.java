/*
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

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class GoogleCloudSigningServiceTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    private SigningService getTestService() {
        return getTestService(true);
    }

    private SigningService getTestService(boolean certificate) {
        return new GoogleCloudSigningService("http://localhost:" + port() + "/", "projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring", "token", alias -> {
            if (!certificate) {
                return null;
            }
            try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                return certificates.toArray(new Certificate[0]);
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("Failed to load the certificate", e);
            }
        });
    }

    @Test
    public void testGetAliases() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/googlecloud-cryptokeys.json"));

        SigningService service = getTestService();
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("hsmkey", "jsign-encrypt", "jsign-rsa-4096-raw", "jsign-rsa-2048", "jsign-rsa-4096"), aliases);
    }

    @Test
    public void testGetAliasesWithError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\": {\"code\": 404,\"message\": \"KeyRing projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring not found.\", \"status\": \"NOT_FOUND\"}}");

        SigningService service = getTestService();

        Exception e = assertThrows(KeyStoreException.class, service::aliases);
        assertEquals("message", "404 - NOT_FOUND: KeyRing projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring not found.", e.getCause().getMessage());
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        SigningService service = getTestService();
        Certificate[] chain = service.getCertificateChain("key1");
        assertNotNull("chain", chain);
        assertEquals("number of certificates", 3, chain.length);
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        testGetPrivateKey("jsign-rsa-2048", true);
    }

    @Test
    public void testGetPrivateKeyWithFullName() throws Exception {
        testGetPrivateKey("projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048", true);
    }

    @Test
    public void testGetPrivateKeyWithVersion() throws Exception {
        testGetPrivateKey("jsign-rsa-2048/cryptoKeyVersions/2", false);
    }

    @Test
    public void testGetPrivateKeyWithVersionAndCertificate() throws Exception {
        testGetPrivateKey("jsign-rsa-2048/cryptoKeyVersions/2", true);
    }

    @Test
    public void testGetPrivateKeyWithVersionAndAlgorithm() throws Exception {
        testGetPrivateKey("jsign-rsa-2048/cryptoKeyVersions/2:RSA", false);
    }

    public void testGetPrivateKey(String alias, boolean certificate) throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048/cryptoKeyVersions")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/googlecloud-cryptokey-versions.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048/cryptoKeyVersions/2")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/googlecloud-cryptokey-version.json"));

        SigningService service = getTestService(certificate);

        SigningServicePrivateKey key = service.getPrivateKey(alias, null);
        assertNotNull("null key", key);
        assertEquals("id", "projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048/cryptoKeyVersions/2", key.getId());
        assertEquals("algorithm", "RSA", key.getAlgorithm());

        // check if the key is cached
        SigningServicePrivateKey key2 = service.getPrivateKey(alias, null);
        assertSame("private key not cached", key, key2);
    }

    @Test
    public void testGetPrivateKeyWithError() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign/cryptoKeyVersions")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"error\": {\"code\": 404, \"message\": \"CryptoKey projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign not found.\", \"status\": \"NOT_FOUND\"}}");

        SigningService service = getTestService();

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("jsign", null));
        assertEquals("message", "Unable to fetch Google Cloud private key 'projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign'", e.getMessage());
        assertEquals("root cause", "404 - NOT_FOUND: CryptoKey projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign not found.", e.getCause().getMessage());
    }

    @Test
    public void testGetPrivateKeyWithNoEnabledVersion() {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign/cryptoKeyVersions")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody("{}");

        SigningService service = getTestService();

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("jsign", null));
        assertEquals("message", "Unable to fetch Google Cloud private key 'projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign', no version found", e.getMessage());
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048/cryptoKeyVersions/2:asymmetricSign")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/googlecloud-sign.json"));

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign-rsa-2048/cryptoKeyVersions/2:RSA", null);
        String signature = Base64.getEncoder().encodeToString(service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("signature", "MiZ/YXfluqyuMfR3cnChG7+K7JmU2b8SzBAc6+WOpWQwIV4GfkLcRe0A68H45Lf+XPiMPPLrs7EqOv1EAnkYDFx5AqZBTWBfoaBeqKpy30OBvNbxIsaTLsaJYGypwmHOUTP+Djz7FxQUyM0uWVfUnHUDT564gQLz0cta6PKE/oMUo9fZhpv5VQcgfrbdUlPaD/cSAOb833ZSRzPWbnqztWO6py5sUugvqGFHKhsEXesx5yrPvJTKu5HVF3QM3E8YrgnVfFK14W8oyTJmXIWQxfYpwm/CW037UmolDMqwc3mjx1758kR+9lOcf8c/LSmD/SVD18SDSK4FyLQWOmn16A==", signature);
    }

    @Test
    public void testSignWithInvalidKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048/cryptoKeyVersions/2:asymmetricSign")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/googlecloud-sign-error.json"));

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign-rsa-2048/cryptoKeyVersions/2:RSA", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "400 - FAILED_PRECONDITION: projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring/cryptoKeys/jsign-rsa-2048/cryptoKeyVersions/2 is not enabled, current state is: DESTROYED.", e.getCause().getMessage());
    }
}
