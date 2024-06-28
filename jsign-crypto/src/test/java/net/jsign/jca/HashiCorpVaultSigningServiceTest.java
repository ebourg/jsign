/**
 * Copyright 2023 Emmanuel Bourg
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

import net.jsign.DigestAlgorithm;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class HashiCorpVaultSigningServiceTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port() + "/", "token", alias -> {
            try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                return certificates.toArray(new Certificate[0]);
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("Failed to load the certificate", e);
            }
        });

        Certificate[] chain = service.getCertificateChain("key1");
        assertNotNull("chain", chain);
        assertEquals("number of certificates", 3, chain.length);
    }

    @Test
    public void testGetAliases() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys")
                .havingQueryStringEqualTo("list=true")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"keys\": [\"key1\", \"key2\", \"key3\"]" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("key1", "key2", "key3"), aliases);
    }

    @Test(expected = KeyStoreException.class)
    public void testGetAliasesError() throws Exception {
        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        service.aliases();
    }

    @Test
    public void testMissingKeyVersion() {
        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        try {
            service.getPrivateKey("key1", null);
            fail("Exception not thrown");
        } catch (UnrecoverableKeyException e) {
            assertEquals("message", "Unable to fetch HashiCorp Vault private key 'key1' (missing key version)", e.getMessage());
        }
    }

    @Test
    public void testGetPrivateKeyGCPKMS() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"id\": \"projects/first-rain-123/locations/global/keyRings/mykeyring/cryptoKeys/key1\", " +
                        "    \"algorithm\": \"rsa_sign_pkcs1_2048_sha256\"" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        SigningServicePrivateKey privateKey = service.getPrivateKey("key1:7", null);
        assertNotNull("privateKey", privateKey);
        assertEquals("keyId", "key1:7", privateKey.getId());
        assertEquals("algorithm", "RSA", privateKey.getAlgorithm());

        // check if the key is cached
        SigningServicePrivateKey privateKey2 = service.getPrivateKey("key1:7", null);
        assertSame("privateKey", privateKey, privateKey2);
    }

    @Test
    public void testGetPrivateKeyTransit() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"type\": \"rsa-2048\"" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        SigningServicePrivateKey privateKey = service.getPrivateKey("key1:7", null);
        assertNotNull("privateKey", privateKey);
        assertEquals("keyId", "key1:7", privateKey.getId());
        assertEquals("algorithm", "RSA", privateKey.getAlgorithm());

        // check if the key is cached
        SigningServicePrivateKey privateKey2 = service.getPrivateKey("key1:7", null);
        assertSame("privateKey", privateKey, privateKey2);
    }

    @Test
    public void testGetPrivateKeyError() {
        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        try {
            service.getPrivateKey("key1:7", null);
            fail("Exception not thrown");
        } catch (UnrecoverableKeyException e) {
            assertEquals("message", "Unable to fetch HashiCorp Vault private key 'key1:7'", e.getMessage());
        }
    }

    @Test
    public void testSignGCPKMS() throws Exception {
        byte[] data = "0123456789ABCDEF0123456789ABCDEF".getBytes();
        byte[] digest = DigestAlgorithm.SHA256.getMessageDigest().digest(data);

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"id\": \"projects/first-rain-123/locations/global/keyRings/mykeyring/cryptoKeys/key1\", " +
                        "    \"algorithm\": \"rsa_sign_pkcs1_2048_sha256\"" +
                        "  }" +
                        "}");

        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .havingBodyEqualTo("{\"key_version\":\"7\",\"digest\":\"" + Base64.getEncoder().encodeToString(digest) + "\"}")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"signature\": \"" + Base64.getEncoder().encodeToString(new byte[32]) + "\"" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        SigningServicePrivateKey privateKey = service.getPrivateKey("key1:7", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", data);
        assertNotNull("signature", signature);
        assertArrayEquals("signature", new byte[32], signature);
    }

    @Test
    public void testSignTransit() throws Exception {
        byte[] data = "0123456789ABCDEF0123456789ABCDEF".getBytes();
        byte[] digest = DigestAlgorithm.SHA384.getMessageDigest().digest(data);

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"type\": \"rsa-2048\"" +
                        "  }" +
                        "}");

        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/sign/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .havingBodyEqualTo("{\"prehashed\":true,\"input\":\"" + Base64.getEncoder().encodeToString(digest) +"\",\"key_version\":\"7\",\"hash_algorithm\":\"sha2-384\",\"signature_algorithm\":\"pkcs1v15\"}")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"signature\": \"vault:v7:" + Base64.getEncoder().encodeToString(new byte[32]) + "\"" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port() , "token", null);
        SigningServicePrivateKey privateKey = service.getPrivateKey("key1:7", null);

        byte[] signature = service.sign(privateKey, "SHA384withRSA", data);
        assertNotNull("signature", signature);
    }

    @Test(expected = GeneralSecurityException.class)
    public void testSignErrorGCPKMS() throws Exception {
        byte[] data = "0123456789ABCDEF0123456789ABCDEF".getBytes();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"id\": \"projects/first-rain-123/locations/global/keyRings/mykeyring/cryptoKeys/key1\", " +
                        "    \"algorithm\": \"rsa_sign_pkcs1_2048_sha256\"" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        SigningServicePrivateKey privateKey = service.getPrivateKey("key1:7", null);

        service.sign(privateKey, "SHA256withRSA", data);
    }

    @Test (expected = GeneralSecurityException.class)
    public void testSignErrorTransit() throws Exception {
        byte[] data = "0123456789ABCDEF0123456789ABCDEF".getBytes();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/keys/key1")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody("{" +
                        "  \"data\": {" +
                        "    \"type\": \"rsa-2048\"" +
                        "  }" +
                        "}");

        SigningService service = new HashiCorpVaultSigningService("http://localhost:" + port(), "token", null);
        SigningServicePrivateKey privateKey = service.getPrivateKey("key1:7", null);

        service.sign(privateKey, "SHA256withRSA", data);
    }
}
