/**
 * Copyright 2022 Emmanuel Bourg
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
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class AmazonSigningServiceTest {

    @Before
    public void setUp() {
        initJadler().withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    private SigningService getTestService() {
        AmazonCredentials credentials = new AmazonCredentials("accessKey", "secretKey", null);
        return new AmazonSigningService(() -> credentials, alias -> {
            try (FileInputStream in = new FileInputStream("target/test-classes/keystores/jsign-test-certificate-full-chain.pem")) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                return certificates.toArray(new Certificate[0]);
            } catch (IOException | CertificateException e) {
                throw new RuntimeException("Failed to load the certificate", e);
            }
        }, "http://localhost:" + port());
    }

    @Test
    public void testGetAliases() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.ListKeys")
                .respond()
                .withStatus(200)
                .withContentType("application/x-amz-json-1.1")
                .withBody(new FileReader("target/test-classes/services/aws-listkeys.json"));

        SigningService service = getTestService();
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("2d9ca5b0-6d51-4727-9dfc-186e62e4c5e2", "935ecb66-5c06-495b-babe-5798b1c0e1a8"), aliases);
    }

    @Test
    public void testGetEndpointUrl() throws Exception {
        // Test default endpoint
        String defaultEndpoint = AmazonSigningService.getEndpointUrl("us-west-2");
        assertEquals("https://kms.us-west-2.amazonaws.com", defaultEndpoint);

        // Test FIPS endpoint
        try (MockedStatic<?> mock = mockStatic(AmazonSigningService.class, CALLS_REAL_METHODS)) {
            when(AmazonSigningService.getenv("AWS_USE_FIPS_ENDPOINT")).thenReturn("true");
            String fipsEndpoint = AmazonSigningService.getEndpointUrl("us-west-2");
            assertEquals("https://kms-fips.us-west-2.amazonaws.com", fipsEndpoint);
        }
    }

    @Test
    public void testGetAliasesWithError() {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.ListKeys")
                .respond()
                .withStatus(400)
                .withContentType("application/x-amz-json-1.1")
                .withBody("{\"__type\":\"UnrecognizedClientException\",\"message\":\"The security token included in the request is invalid.\"}");

        SigningService service = getTestService();
        try {
            service.aliases();
            fail("Exception not thrown");
        } catch (KeyStoreException e) {
            assertEquals("message", "UnrecognizedClientException: The security token included in the request is invalid.", e.getCause().getMessage());
        }
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        SigningService service = getTestService();
        Certificate[] chain = service.getCertificateChain("key1");
        assertNotNull("chain", chain);
        assertEquals("number of certificates", 3, chain.length);
    }

    @Test
    public void testGetPrivateKeyRSA() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-rsa.json"));

        SigningService service = getTestService();

        SigningServicePrivateKey key = service.getPrivateKey("jsign-rsa-2048", null);
        assertNotNull("null key", key);
        assertEquals("id", "jsign-rsa-2048", key.getId());
        assertEquals("algorithm", "RSA", key.getAlgorithm());

        // check if the key is cached
        SigningServicePrivateKey key2 = service.getPrivateKey("jsign-rsa-2048", null);
        assertSame("private key not cached", key, key2);
    }

    @Test
    public void testGetPrivateKeyEC() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-ec.json"));

        SigningService service = getTestService();

        SigningServicePrivateKey key = service.getPrivateKey("jsign-ec-384", null);
        assertNotNull("null key", key);
        assertEquals("id", "jsign-ec-384", key.getId());
        assertEquals("algorithm", "EC", key.getAlgorithm());

        // check if the key is cached
        SigningServicePrivateKey key2 = service.getPrivateKey("jsign-ec-384", null);
        assertSame("private key not cached", key, key2);
    }

    @Test
    public void testGetPrivateKeyDisabled() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-disabled.json"));

        SigningService service = getTestService();

        try {
            service.getPrivateKey("jsign-rsa-2048", null);
            fail("Exception not thrown");
        } catch (UnrecoverableKeyException e) {
            assertEquals("message", "The key 'jsign-rsa-2048' is not enabled (PendingImport)", e.getMessage());
        }
    }

    @Test
    public void testGetPrivateKeyWithWrongUsage() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-encrypt.json"));

        SigningService service = getTestService();

        try {
            service.getPrivateKey("jsign-rsa-2048", null);
            fail("Exception not thrown");
        } catch (UnrecoverableKeyException e) {
            assertEquals("message", "The key 'jsign-rsa-2048' is not a signing key", e.getMessage());
        }
    }

    @Test
    public void testGetPrivateKeyWithError() {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody("{\"__type\":\"NotFoundException\",\"message\":\"Alias arn:aws:kms:eu-west-3:829022948260:alias/jsign-rsa-2048 is not found.\"}");

        SigningService service = getTestService();

        try {
            service.getPrivateKey("jsign-rsa-2048", null);
            fail("Exception not thrown");
        } catch (UnrecoverableKeyException e) {
            assertEquals("message", "NotFoundException: Alias arn:aws:kms:eu-west-3:829022948260:alias/jsign-rsa-2048 is not found.", e.getCause().getMessage());
        }
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-rsa.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.Sign")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-sign.json"));

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign-rsa-2048", null);
        String signature = Base64.getEncoder().encodeToString(service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("signature", "MiZ/YXfluqyuMfR3cnChG7+K7JmU2b8SzBAc6+WOpWQwIV4GfkLcRe0A68H45Lf+XPiMPPLrs7EqOv1EAnkYDFx5AqZBTWBfoaBeqKpy30OBvNbxIsaTLsaJYGypwmHOUTP+Djz7FxQUyM0uWVfUnHUDT564gQLz0cta6PKE/oMUo9fZhpv5VQcgfrbdUlPaD/cSAOb833ZSRzPWbnqztWO6py5sUugvqGFHKhsEXesx5yrPvJTKu5HVF3QM3E8YrgnVfFK14W8oyTJmXIWQxfYpwm/CW037UmolDMqwc3mjx1758kR+9lOcf8c/LSmD/SVD18SDSK4FyLQWOmn16A==", signature);
    }

    @Test
    public void testSignWithInvalidAlgorithm() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-rsa.json"));

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign-rsa-2048", null);
        try {
            service.sign(privateKey, "SHA1withRSA", "Hello".getBytes());
            fail("Exception not thrown");
        } catch (GeneralSecurityException e) {
            assertEquals("message", "Unsupported signing algorithm: SHA1withRSA", e.getMessage());
        }
    }

    @Test
    public void testSignWithError() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.DescribeKey")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/aws-describekey-rsa.json"));
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/")
                .havingHeaderEqualTo("X-Amz-Target", "TrentService.Sign")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody("{\"__type\":\"KMSInvalidStateException\",\"message\":\"arn:aws:kms:eu-west-3:829022948260:key/935ecb66-5c06-495b-babe-5798b1c0e1a8 is pending deletion.\"}");

        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("jsign-rsa-2048", null);
        try {
            service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());
            fail("Exception not thrown");
        } catch (GeneralSecurityException e) {
            assertEquals("message", "KMSInvalidStateException: arn:aws:kms:eu-west-3:829022948260:key/935ecb66-5c06-495b-babe-5798b1c0e1a8 is pending deletion.", e.getCause().getMessage());
        }
    }

    @Test
    public void testSignRequestWithoutSessionToken() throws Exception {
        testSignRequest(false);
    }

    @Test
    public void testSignRequestWithSessionToken() throws Exception {
        testSignRequest(true);
    }

    public void testSignRequest(boolean useSessionToken) throws Exception {
        AmazonCredentials credentials = new AmazonCredentials("accessKey", "secretKey",useSessionToken ? "sessionToken" : null);
        AmazonSigningService service = new AmazonSigningService("eu-west-3", credentials, null);

        URL url = new URL("https://kms.eu-west-3.amazonaws.com");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("User-Agent", "Jsign (https://ebourg.github.io/jsign/)");
        conn.setRequestProperty("X-Amz-Target", "TrentService.ListKeys");
        conn.setRequestProperty("Content-Type", "application/x-amz-json-1.1");
        service.sign(conn, credentials, "{}".getBytes(), new Date(0));

        assertEquals("X-Amz-Date", "19700101T000000Z", conn.getRequestProperty("X-Amz-Date"));
        assertEquals("X-Amz-Security-Token", credentials.getSessionToken(), conn.getRequestProperty("X-Amz-Security-Token"));
        assertEquals("Authorization", "AWS4-HMAC-SHA256 Credential=accessKey/19700101/eu-west-3/kms/aws4_request, SignedHeaders=content-type;host;user-agent;x-amz-date;x-amz-target, Signature=6247e3c7f2e50e806e32843924b94c860b6a3721fd12f9b99d8d8d140795e4c5", getAuthorizationHeaderValue(conn));
    }

    private String getAuthorizationHeaderValue(HttpURLConnection conn) throws Exception {
        Field delegate = sun.net.www.protocol.https.HttpsURLConnectionImpl.class.getDeclaredField("delegate");
        Field requests = sun.net.www.protocol.http.HttpURLConnection.class.getDeclaredField("requests");
        AccessibleObject.setAccessible(new Field[]{delegate, requests}, true);
        sun.net.www.MessageHeader headers = (sun.net.www.MessageHeader) requests.get(delegate.get(conn));
        return headers.findValue("Authorization");
    }
}
