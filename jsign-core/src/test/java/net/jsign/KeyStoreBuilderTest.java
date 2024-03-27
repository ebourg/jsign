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

package net.jsign;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.ProviderException;

import org.apache.commons.io.FileUtils;
import org.junit.Assume;
import org.junit.Test;

import net.jsign.jca.OpenPGPCardTest;
import net.jsign.jca.PIVCardTest;

import static net.jsign.KeyStoreType.*;
import static org.junit.Assert.*;

public class KeyStoreBuilderTest {

    @Test
    public void testCreateFile() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder();
        File file = builder.createFile(null);

        assertNull(file);

        // relative path, default base directory
        file = builder.createFile("keystore.p12");
        assertEquals(new File(".").getCanonicalFile(), file.getCanonicalFile().getParentFile());
        assertEquals("keystore.p12", file.getName());

        // relative path, custom base directory
        builder.setBaseDir(new File("target/test-classes"));
        file = builder.createFile("keystores/keystore.p12");
        assertEquals(new File("target/test-classes/keystores").getCanonicalFile(), file.getCanonicalFile().getParentFile());
        assertEquals("keystore.p12", file.getName());

        // absolute path
        builder.setBaseDir(new File("target/test-classes/keystores"));
        file = builder.createFile(new File("keystore.p12").getAbsolutePath());
        assertEquals(new File(".").getCanonicalFile(), file.getCanonicalFile().getParentFile());
        assertEquals("keystore.p12", file.getName());
    }

    @Test
    public void testReadPasswordFromEnvironment() {
        Assume.assumeTrue("STOREPASS environment variable not defined", System.getenv().containsKey("STOREPASS"));

        KeyStoreBuilder builder = new KeyStoreBuilder().storepass("env:STOREPASS");

        assertEquals("password", builder.storepass());
    }

    @Test
    public void testReadPasswordFromEnvironmentFailed() {
        Assume.assumeFalse(System.getenv().containsKey("MISSING_VAR"));

        KeyStoreBuilder builder = new KeyStoreBuilder().storepass("env:MISSING_VAR");

        try {
            builder.storepass();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "Failed to read the storepass parameter, the 'MISSING_VAR' environment variable is not defined", e.getMessage());
        }
    }

    @Test
    public void testReadPasswordFromFile() throws Exception {
        Files.write(new File("target/test-classes/storepass.txt").toPath(), "password".getBytes());

        KeyStoreBuilder builder = new KeyStoreBuilder().storepass("file:target/test-classes/storepass.txt");

        assertEquals("password", builder.storepass());
    }

    @Test
    public void testReadPasswordFromFileFailed() {
        KeyStoreBuilder builder = new KeyStoreBuilder().storepass("file:/path/to/missing/file");

        try {
            builder.storepass();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "Failed to read the storepass parameter from the file '/path/to/missing/file'", e.getMessage());
        }
    }

    @Test
    public void testBuildAWS() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(AWS);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must specify the AWS region", e.getMessage());
        }

        builder.keystore("eu-west-1");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "certfile parameter must be set", e.getMessage());
        }

        builder.certfile("keystores/jsign-test-certificate.pem");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertTrue("message", e.getMessage().matches(
                    "storepass parameter must specify the AWS credentials\\: \\<accessKey\\>\\|\\<secretKey\\>\\[\\|\\<sessionToken\\>\\], when not running from an EC2 instance \\(.*\\)"));
        }

        builder.storepass("<accessKey>|<secretKey>|<sessionToken>");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildAzureKeyVault() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(AZUREKEYVAULT);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must specify the Azure vault name", e.getMessage());
        }

        builder.keystore("jsigntestkeyvault");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the Azure API access token", e.getMessage());
        }

        builder.storepass("0123456789ABCDEF");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildDigiCertONE() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(DIGICERTONE);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>", e.getMessage());
        }

        builder.storepass("0123456789ABCDEF");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>", e.getMessage());
        }

        builder.storepass("APIKEY|keystore.p12|password");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (Exception e) {
            assertEquals("message", "Failed to load the client certificate for DigiCert ONE", e.getMessage());
        }

        builder.storepass("APIKEY|target/test-classes/keystores/keystore.p12|password");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }


    @Test
    public void testBuildESigner() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(ESIGNER);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the SSL.com username and password: <username>|<password>", e.getMessage());
        }

        builder.storepass("password");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the SSL.com username and password: <username>|<password>", e.getMessage());
        }

        builder.storepass("esigner_test|esignerTest#1");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalStateException e) {
            assertEquals("message", "Authentication failed with SSL.com", e.getMessage());
        }

        builder.storepass("esigner_demo|esignerDemo#1");
        builder.keystore("https://cs-try.ssl.com");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildGoogleCloud() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(GOOGLECLOUD);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must specify the Goole Cloud keyring", e.getMessage());
        }

        builder.keystore("projects/first-rain-123/locations/global/keyRings/mykeyring");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the Goole Cloud API access token", e.getMessage());
        }

        builder.storepass("0123456789ABCDEF");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "certfile parameter must be set", e.getMessage());
        }

        builder.certfile("keystores/jsign-test-certificate.pem");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildHashiCorpVault() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(HASHICORPVAULT);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must specify the HashiCorp Vault secrets engine URL", e.getMessage());
        }

        builder.keystore("https://vault.example.com:8200/v1/gcpkms/");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the HashiCorp Vault token", e.getMessage());
        }

        builder.storepass("0123456789ABCDEF");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "certfile parameter must be set", e.getMessage());
        }

        builder.certfile("keystores/jsign-test-certificate.pem");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildOracleCloud() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(ORACLECLOUD);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "certfile parameter must be set", e.getMessage());
        }

        builder.certfile("keystores/jsign-test-certificate.pem");

        File config = File.createTempFile("ociconfig", null);
        config.deleteOnExit();
        FileUtils.writeStringToFile(config, "[DEFAULT]\n", "UTF-8");

        builder.storepass(config.getAbsolutePath());

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildJKS() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(JKS);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must be set", e.getMessage());
        }

        builder.keystore("target/test-classes/keystores/keystore.jks");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildJCEKS() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(JCEKS);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must be set", e.getMessage());
        }

        builder.keystore("target/test-classes/keystores/keystore.jceks");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildPKCS12() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(PKCS12);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must be set", e.getMessage());
        }

        builder.keystore("target/test-classes/keystores/keystore.p12");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildPKCS11() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(PKCS11);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter must be set", e.getMessage());
        }

        builder.keystore("target/test-classes/pkcs11-missing.cfg");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "keystore parameter should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security", e.getMessage());
        }

        builder.keystore("target/test-classes/keystores/keystore.p12");

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (ProviderException e) {
            assertEquals("message", "Failed to create a SunPKCS11 provider from the configuration target/test-classes/keystores/keystore.p12", e.getMessage());
        }
    }

    @Test
    public void testBuildOpenPGP() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(OPENPGP);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the PIN", e.getMessage());
        }

        OpenPGPCardTest.assumeCardPresent();

        builder.storepass("123456");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildPIV() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(PIV);

        try {
            builder.build();
            fail("Exception not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("message", "storepass parameter must specify the PIN", e.getMessage());
        }

        PIVCardTest.assumeCardPresent();

        builder.storepass("123456");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testLowerCaseStoreType() {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype("pkcs12");
        assertEquals("storetype", PKCS12, builder.storetype());
    }
}
