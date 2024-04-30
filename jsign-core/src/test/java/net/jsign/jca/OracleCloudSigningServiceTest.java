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
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class OracleCloudSigningServiceTest {

    @Before
    public void setUp() {
        initJadlerListeningOn(18080).withDefaultResponseStatus(404);
    }

    @After
    public void tearDown() {
        closeJadler();
    }

    private OracleCloudCredentials getCredentials() throws Exception {
        File config = File.createTempFile("ociconfig", null);
        FileUtils.writeStringToFile(config, "[DEFAULT]\n" +
                "user=ocid1.user.oc1..abcdefghijk\n" +
                "tenancy=ocid1.tenancy.oc1..abcdefghijk\n" +
                "region=eu-paris-1\n" +
                "key_file=src/test/resources/keystores/privatekey.pkcs8.pem\n" +
                "fingerprint=97:a2:2f:f5:e8:39:d3:44:b7:63:f2:4e:31:18:a6:62\n" +
                "pass_phrase=password\n", "UTF-8");

        OracleCloudCredentials credentials = new OracleCloudCredentials();
        credentials.load(config, "DEFAULT");
        return credentials;
    }

    private SigningService getTestService() throws Exception {
        return new OracleCloudSigningService(getCredentials(), alias -> {
            try {
                try (FileInputStream in = new FileInputStream("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")) {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
                    return certificates.toArray(new Certificate[0]);
                }
            } catch (IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
        }) {
            @Override
            String getVaultEndpoint() {
                return "http://localhost:" + port();
            }

            @Override
            String getKeyEndpoint(String keyId) {
                return "http://localhost:" + port();
            }
        };
    }

    @Test
    public void testGetVaultEndpoint() throws Exception {
        OracleCloudCredentials credentials = getCredentials();
        OracleCloudSigningService service = new OracleCloudSigningService(credentials, alias -> null);
        assertEquals("endpoint", "https://kms.eu-paris-1.oraclecloud.com", service.getVaultEndpoint());
    }

    @Test
    public void testGetKeyEndpoint() throws Exception {
        OracleCloudCredentials credentials = getCredentials();
        OracleCloudSigningService service = new OracleCloudSigningService(credentials, alias -> null);
        String keyId = "ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza";
        assertEquals("endpoint", "https://h5tafwboaahxq-crypto.kms.eu-paris-1.oci.oraclecloud.com", service.getKeyEndpoint(keyId));
    }

    @Test
    public void testGetKeyEndpointWithInvalidKey() throws Exception {
        OracleCloudCredentials credentials = getCredentials();
        OracleCloudSigningService service = new OracleCloudSigningService(credentials, alias -> null);
        String keyId = "ocid1.tenancy.oc1..abcdefghijk";
        try {
            service.getKeyEndpoint(keyId);
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "Invalid key id: ocid1.tenancy.oc1..abcdefghijk", e.getMessage());
        }
    }

    @Test
    public void testIsUnknownHost() throws Exception {
        OracleCloudCredentials credentials = getCredentials();
        OracleCloudSigningService service = new OracleCloudSigningService(credentials, alias -> null);

        assertFalse(service.isUnknownHost("google.com"));
        assertTrue(service.isUnknownHost("google.jsign"));
    }

    @Test
    public void testGetAliases() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/20180608/vaults")
                .havingQueryStringEqualTo("compartmentId=ocid1.tenancy.oc1..abcdefghijk")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/oraclecloud-listvaults.json"));
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/20180608/keys")
                .havingQueryStringEqualTo("compartmentId=ocid1.tenancy.oc1..abcdefghijk")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/oraclecloud-listkeys.json"));

        SigningService service = getTestService();
        List<String> aliases = service.aliases();

        assertEquals("aliases", Arrays.asList("ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza",
                "ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljr7tub2mmyv5x2w6hwdlbpa3l567vih67yypquqkm4pjgk4cx7rkpa"), aliases);
    }

    @Test(expected = KeyStoreException.class)
    public void testGetAliasesWithError() throws Exception {
        onRequest()
                .havingMethodEqualTo("GET")
                .havingPathEqualTo("/20180608/vaults")
                .havingQueryStringEqualTo("compartmentId=ocid1.tenancy.oc1..abcdefghijk")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody("{\"code\":\"InvalidParameter\", \"message\":\"The compartmentId must be an ocid.\"}");

        SigningService service = getTestService();
        service.aliases();
    }

    @Test
    public void testSign() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/20180608/sign")
                .respond()
                .withStatus(200)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/oraclecloud-sign.json"));
        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza", null);
        String signature = Base64.getEncoder().encodeToString(service.sign(privateKey, "SHA256withRSA", "Hello".getBytes()));
        assertEquals("signature", "MiZ/YXfluqyuMfR3cnChG7+K7JmU2b8SzBAc6+WOpWQwIV4GfkLcRe0A68H45Lf+XPiMPPLrs7EqOv1EAnkYDFx5AqZBTWBfoaBeqKpy30OBvNbxIsaTLsaJYGypwmHOUTP+Djz7FxQUyM0uWVfUnHUDT564gQLz0cta6PKE/oMUo9fZhpv5VQcgfrbdUlPaD/cSAOb833ZSRzPWbnqztWO6py5sUugvqGFHKhsEXesx5yrPvJTKu5HVF3QM3E8YrgnVfFK14W8oyTJmXIWQxfYpwm/CW037UmolDMqwc3mjx1758kR+9lOcf8c/LSmD/SVD18SDSK4FyLQWOmn16A==", signature);
    }

    @Test
    public void testSignWithInvalidKey() throws Exception {
        onRequest()
                .havingMethodEqualTo("POST")
                .havingPathEqualTo("/20180608/sign")
                .respond()
                .withStatus(404)
                .withContentType("application/json")
                .withBody(new FileReader("target/test-classes/services/oraclecloud-error.json"));
        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("ocid1.key.oc1.eu-paris-2.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza", null);
        try {
            service.sign(privateKey, "SHA256withRSA", "Hello".getBytes());
            fail("Exception not thrown");
        } catch (GeneralSecurityException e) {
            assertEquals("message", "NotAuthorizedOrNotFound: resource does not exist or you are not authorized to access it.", e.getCause().getMessage());
        }
    }

    @Test
    public void testSignWithInvalidAlgorithm() throws Exception {
        SigningService service = getTestService();
        SigningServicePrivateKey privateKey = service.getPrivateKey("ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza", null);
        try {
            service.sign(privateKey, "SHA1withRSA", "Hello".getBytes());
            fail("Exception not thrown");
        } catch (GeneralSecurityException e) {
            assertEquals("message", "Unsupported signing algorithm: SHA1withRSA", e.getMessage());
        }
    }
}
