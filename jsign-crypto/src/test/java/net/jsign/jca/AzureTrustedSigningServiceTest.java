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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.cedarsoftware.util.io.JsonReader;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class AzureTrustedSigningServiceTest {

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
        SigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        List<String> aliases = service.aliases();

        assertEquals("aliases", Collections.emptyList(), aliases);
    }

    @Test
    public void testGetCertificateChain() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
        .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile:sign")
        .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(202)
        .withHeader("operation-location", "http://localhost:" + port() + "/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb?api-version=2023-06-15-preview")
        .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}");
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb")
        .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(200)
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}")
                .thenRespond()
                .withStatus(200)
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}")
                .thenRespond()
                .withStatus(200)
                .withBody(loadSignSuccessResponse());

        SigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        Certificate[] chain = service.getCertificateChain("MyAccount/MyProfile");
        assertNotNull("null chain", chain);
        assertEquals("length", 4, chain.length);
        assertEquals("subject 1", "CN=Emmanuel Bourg, O=Emmanuel Bourg, L=Paris, ST=Ile de France, C=FR", ((X509Certificate) chain[0]).getSubjectDN().getName());
        assertEquals("subject 2", "CN=Microsoft ID Verified CS EOC CA 01, O=Microsoft Corporation, C=US", ((X509Certificate) chain[1]).getSubjectDN().getName());
        assertEquals("subject 3", "CN=Microsoft ID Verified Code Signing PCA 2021, O=Microsoft Corporation, C=US", ((X509Certificate) chain[2]).getSubjectDN().getName());
        assertEquals("subject 4", "CN=Microsoft Identity Verification Root Certificate Authority 2020, O=Microsoft Corporation, C=US", ((X509Certificate) chain[3]).getSubjectDN().getName());
    }

    @Test
    public void testGetCertificateChainWithError() {
        onRequest()
                .havingMethodEqualTo("POST")
        .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile:sign")
        .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(403);

        SigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");

        Exception e = assertThrows(KeyStoreException.class, () -> service.getCertificateChain("MyAccount/MyProfile"));
        assertEquals("message", "Unable to retrieve the certificate chain 'MyAccount/MyProfile'", e.getMessage());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        SigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("MyAccount/MyProfile", null);
        assertNotNull("null key", privateKey);
        assertEquals("id", "MyAccount/MyProfile", privateKey.getId());
        assertEquals("algorithm", "RSA", privateKey.getAlgorithm());
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile:sign")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(202)
                .withHeader("operation-location", "http://localhost:" + port() + "/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb?api-version=2023-06-15-preview")
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}");
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(200)
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}")
                .thenRespond()
                .withStatus(200)
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}")
                .thenRespond()
                .withStatus(200)
                .withBody(loadSignSuccessResponse());

        AzureTrustedSigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("MyAccount/MyProfile", null);

        byte[] signature = service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());

        assertNotNull("null signature", signature);
        assertEquals("length", 384, signature.length);
    }

    @Test
    public void testSignWithTimeout() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile:sign")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(202)
                .withHeader("operation-location", "http://localhost:" + port() + "/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb?api-version=2023-06-15-preview")
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}");
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(200)
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}");

        AzureTrustedSigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        service.setTimeout(2);
        SigningServicePrivateKey privateKey = service.getPrivateKey("MyAccount/MyProfile", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Signing operation 1f234bd9-16cf-4283-9ee6-a460d31207bb timed out", e.getMessage());
    }

    @Test
    public void testSignWithFailure() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile:sign")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(202)
                .withHeader("operation-location", "http://localhost:" + port() + "/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb?api-version=2023-06-15-preview")
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"InProgress\",\"signature\":null,\"signingCertificate\":null}");
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile/sign/1f234bd9-16cf-4283-9ee6-a460d31207bb")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(200)
                .withBody("{\"operationId\":\"1f234bd9-16cf-4283-9ee6-a460d31207bb\",\"status\":\"Failed\",\"signature\":null,\"signingCertificate\":null}");

        AzureTrustedSigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("MyAccount/MyProfile", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "java.io.IOException: Signing operation 1f234bd9-16cf-4283-9ee6-a460d31207bb failed: Failed", e.getMessage());
    }

    @Test
    public void testSignWithInvalidAlgorithm() throws Exception {
        SigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("MyAccount/MyProfile", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA1withRSA", "Hello".getBytes()));
        assertEquals("message", "Unsupported signing algorithm: SHA1withRSA", e.getMessage());
    }

    @Test
    public void testSignWithAuthorizationError() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/codesigningaccounts/MyAccount/certificateprofiles/MyProfile:sign")
                .havingQueryStringEqualTo("api-version=2023-06-15-preview")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody("{\"errorDetail\":{\"code\":\"InternalError\",\"message\":\"Response status code does not indicate success: 403 (Forbidden).\",\"target\":null}}");

        AzureTrustedSigningService service = new AzureTrustedSigningService("http://localhost:" + port(), "token");
        SigningServicePrivateKey privateKey = service.getPrivateKey("MyAccount/MyProfile", null);

        Exception e = assertThrows(GeneralSecurityException.class, () -> service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("message", "InternalError - Response status code does not indicate success: 403 (Forbidden).", e.getCause().getMessage());
    }

        private String loadSignSuccessResponse() throws Exception {
                String json = new String(Files.readAllBytes(Paths.get("target/test-classes/services/trustedsigning-sign.json")), StandardCharsets.UTF_8);
                Map<String, Object> response = (Map<String, Object>) JsonReader.jsonToJava(json);
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("operationId", response.get("operationId"));
                payload.put("status", response.get("status"));
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("signature", response.get("signature"));
                result.put("signingCertificate", response.get("signingCertificate"));
                payload.put("result", result);
                return JsonWriter.format(payload);
        }
}
