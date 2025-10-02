/*
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

import java.io.FileReader;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import net.jsign.DigestAlgorithm;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class AzureKeyVaultSigningServiceTest {

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
                .havingPathEqualTo("/certificates")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificates.json"));

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("test1", "test2", "test3"), aliases);
    }

    @Test
    public void testGetAliasesError() {
        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");

        Exception e = assertThrows(KeyStoreException.class, service::aliases);
        assertEquals("message", "Unable to retrieve Azure Key Vault certificate aliases", e.getMessage());
    }

    @Test
    public void testGetAliasesFromJarSigner() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(403)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/azure-certificates-error.json"));

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        List<String> aliases = new jarsigner().apply(service);

        assertEquals("aliases", Collections.emptyList(), aliases);
    }

    private static final class jarsigner implements Function<SigningService, List<String>> {
        public List<String> apply(SigningService service) {
            try {
                return service.aliases();
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates/test1")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificate.json"));

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        Certificate[] chain = service.getCertificateChain("test1");
        assertNotNull("chain", chain);
        assertEquals("number of certificates", 1, chain.length);
        assertEquals("subject name", "CN=Jsign Code Signing Test Certificate 2024 (RSA)", ((X509Certificate) chain[0]).getSubjectDN().getName());

        // check if the certificate is cached
        Certificate[] chain2 = service.getCertificateChain("test1");
        assertEquals("certificate", chain[0], chain2[0]);
    }

    @Test
    public void testGetCertificateChainError() {
        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("test1"));
        assertEquals("message", "Unable to retrieve Azure Key Vault certificate 'test1'", e.getMessage());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates/test1")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificate.json"));

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("test1", null);
        assertNotNull("privateKey", privateKey);
        assertEquals("algorithm", "https://jsigntestkeyvault.vault.azure.net/keys/test1/38ca3e3560b94086ac604c5dd21aa055", privateKey.getId());
        assertEquals("algorithm", "RSA", privateKey.getAlgorithm());
    }

    @Test
    public void testGetPrivateKeyError() {
        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");

        Exception e = assertThrows(UnrecoverableKeyException.class, () -> service.getPrivateKey("test1", null));
        assertEquals("message", "Unable to fetch Azure Key Vault private key for the certificate 'test1'", e.getMessage());
    }

    @Test
    public void testSign() throws Exception {
        byte[] data = "0123456789ABCDEF0123456789ABCDEF".getBytes();
        byte[] digest = DigestAlgorithm.SHA256.getMessageDigest().digest(data);

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates/test1")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificate.json"));

        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keys/test1/38ca3e3560b94086ac604c5dd21aa055/sign")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .havingBodyEqualTo("{\"alg\":\"RS256\",\"value\":\"" + Base64.getEncoder().encodeToString(digest) + "\"}")
                .respond()
                .withStatus(200)
                .withBody("{\"kid\":\"https://jsigntestkeyvault.vault.azure.net/keys/test1/38ca3e3560b94086ac604c5dd21aa055\",\"value\":\"" + Base64.getEncoder().encodeToString(new byte[32]) + "\"}");

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("test1", null);
        String keyId = privateKey.getId().replace("https://jsigntestkeyvault.vault.azure.net", "http://localhost:" + port());
        privateKey = new SigningServicePrivateKey(keyId, privateKey.getAlgorithm(), service);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", data);
        assertNotNull("signature", signature);
        assertArrayEquals("signature", new byte[32], signature);
    }

    @Test
    public void testSignWithRSNULL() throws Exception {
        byte[] data = "0123456789ABCDEF0123456789ABCDEF".getBytes();

        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates/test1")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificate.json"));

        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/keys/test1/38ca3e3560b94086ac604c5dd21aa055/sign")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .havingBodyEqualTo("{\"alg\":\"RSNULL\",\"value\":\"MCEwCQYFKw4DAhoFAAQUTYV9JAiwDD3RfwxP/PFbl/EEmGc=\"}")
                .respond()
                .withStatus(200)
                .withBody("{\"kid\":\"https://jsigntestkeyvault.vault.azure.net/keys/test1/38ca3e3560b94086ac604c5dd21aa055\",\"value\":\"" + Base64.getEncoder().encodeToString(new byte[32]) + "\"}");

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("test1", null);
        String keyId = privateKey.getId().replace("https://jsigntestkeyvault.vault.azure.net", "http://localhost:" + port());
        privateKey = new SigningServicePrivateKey(keyId, privateKey.getAlgorithm(), service);

        byte[] signature = service.sign(privateKey, "SHA1withRSA", data);
        assertNotNull("signature", signature);
        assertArrayEquals("signature", new byte[32], signature);
    }

    @Test
    public void testSignWithUnsupportedAlgorithm() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates/test1")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificate.json"));

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("test1", null);

        Exception e = assertThrows(InvalidAlgorithmParameterException.class, () -> service.sign(privateKey, "MD5withRSA", new byte[0]));
        assertEquals("message", "Unsupported signing algorithm: MD5withRSA", e.getMessage());
    }

    @Test
    public void testSignError() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/certificates/test1")
                .havingQueryStringEqualTo("api-version=7.2")
                .havingHeaderEqualTo("Authorization", "Bearer token")
                .respond()
                .withStatus(200)
                .withBody(new FileReader("target/test-classes/services/azure-certificate.json"));

        SigningService service = new AzureKeyVaultSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("test1", null);
        String keyId = privateKey.getId().replace("https://jsigntestkeyvault.vault.azure.net", "http://localhost:" + port());
        SigningServicePrivateKey privateKey2 = new SigningServicePrivateKey(keyId, privateKey.getAlgorithm(), service);

        assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey2, "SHA256withRSA", new byte[0]));
    }
}
