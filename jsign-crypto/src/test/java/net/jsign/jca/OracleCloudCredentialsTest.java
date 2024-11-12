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
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.mockito.MockedStatic;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class OracleCloudCredentialsTest {

    private File getSingleProfileConfiguration() throws Exception  {
        String configuration = "[DEFAULT]\n" +
                "user=ocid1.user.oc1..abcdefghijk\n" +
                "tenancy=ocid1.tenancy.oc1..abcdefghijk\n" +
                "region=eu-paris-1\n" +
                "key_file=target/test-classes/keystores/privatekey.pkcs8.pem\n" +
                "fingerprint=97:a2:2f:f5:e8:39:d3:44:b7:63:f2:4e:31:18:a6:62\n" +
                "pass_phrase=password\n";

        File config = File.createTempFile("ociconfig", null);
        config.deleteOnExit();
        FileUtils.writeStringToFile(config, configuration, "UTF-8");

        return config;
    }

    private File getMultiProfileConfiguration() throws Exception {
        String configuration = "[DEFAULT]\n" +
                "user=ocid1.user.oc1..abcdefghijk\n" +
                "tenancy=ocid1.tenancy.oc1..abcdefghijk\n" +
                "region=eu-paris-1\n" +
                "key_file=target/test-classes/keystores/privatekey.pkcs8.pem\n" +
                "fingerprint=97:a2:2f:f5:e8:39:d3:44:b7:63:f2:4e:31:18:a6:62\n" +
                "pass_phrase=password\n" +
                "\n" +
                "[TEST]\n" +
                "user=ocid1.user.oc1..mnopqrstuvw\n" +
                "tenancy=ocid1.tenancy.oc1..mnopqrstuvw\n" +
                "region=eu-milan-1\n" +
                "key_file=target/test-classes/keystores/privatekey.pkcs1.pem\n" +
                "fingerprint=b7:63:f2:4e:31:18:a6:62:97:a2:2f:f5:e8:39:d3:44\n" +
                "pass_phrase=secret\n";

        File config = File.createTempFile("ociconfig", null);
        config.deleteOnExit();
        FileUtils.writeStringToFile(config, configuration, "UTF-8");

        return config;
    }

    @Test
    public void testLoadProfile() throws Exception {
        File config = getMultiProfileConfiguration();

        OracleCloudCredentials credentials = new OracleCloudCredentials();
        credentials.load(config, "TEST");

        assertEquals("user", "ocid1.user.oc1..mnopqrstuvw", credentials.getUser());
        assertEquals("tenancy", "ocid1.tenancy.oc1..mnopqrstuvw", credentials.getTenancy());
        assertEquals("region", "eu-milan-1", credentials.getRegion());
        assertEquals("keyfile", "target/test-classes/keystores/privatekey.pkcs1.pem", credentials.getKeyfile());
        assertEquals("fingerprint", "b7:63:f2:4e:31:18:a6:62:97:a2:2f:f5:e8:39:d3:44", credentials.getFingerprint());
        assertEquals("pass phrase", "secret", credentials.getPassphrase());
        assertEquals("keyid", "ocid1.tenancy.oc1..mnopqrstuvw/ocid1.user.oc1..mnopqrstuvw/b7:63:f2:4e:31:18:a6:62:97:a2:2f:f5:e8:39:d3:44", credentials.getKeyId());
    }

    @Test
    public void testLoadInvalidProfile() throws Exception {
        File config = getMultiProfileConfiguration();

        OracleCloudCredentials credentials = new OracleCloudCredentials();

        Exception e = assertThrows(IOException.class, () -> credentials.load(config, "JSIGN"));
        assertTrue("message", e.getMessage().contains("Profile 'JSIGN' not found"));
    }

    @Test
    public void testLoadFromEnvironment() {
        try (MockedStatic<?> mock = mockStatic(OracleCloudCredentials.class, CALLS_REAL_METHODS)) {
            when(OracleCloudCredentials.getenv("OCI_CLI_USER")).thenReturn("ocid1.user.oc1..abcdefghijk");
            when(OracleCloudCredentials.getenv("OCI_CLI_TENANCY")).thenReturn("ocid1.tenancy.oc1..abcdefghijk");
            when(OracleCloudCredentials.getenv("OCI_CLI_REGION")).thenReturn("eu-paris-1");
            when(OracleCloudCredentials.getenv("OCI_CLI_KEY_FILE")).thenReturn("target/test-classes/keystores/privatekey.pkcs8.pem");
            when(OracleCloudCredentials.getenv("OCI_CLI_FINGERPRINT")).thenReturn("97:a2:2f:f5:e8:39:d3:44:b7:63:f2:4e:31:18:a6:62");
            when(OracleCloudCredentials.getenv("OCI_CLI_PASS_PHRASE")).thenReturn("password");

            OracleCloudCredentials credentials = new OracleCloudCredentials();
            credentials.loadFromEnvironment();

            assertEquals("user", "ocid1.user.oc1..abcdefghijk", credentials.getUser());
            assertEquals("tenancy", "ocid1.tenancy.oc1..abcdefghijk", credentials.getTenancy());
            assertEquals("region", "eu-paris-1", credentials.getRegion());
            assertEquals("keyfile", "target/test-classes/keystores/privatekey.pkcs8.pem", credentials.getKeyfile());
            assertEquals("fingerprint", "97:a2:2f:f5:e8:39:d3:44:b7:63:f2:4e:31:18:a6:62", credentials.getFingerprint());
            assertEquals("pass phrase", "password", credentials.getPassphrase());
        }
    }

    @Test
    public void testOverrideFromEnvironment() throws Exception {
        try (MockedStatic<?> mock = mockStatic(OracleCloudCredentials.class, CALLS_REAL_METHODS)) {
            when(OracleCloudCredentials.getenv("OCI_CLI_USER")).thenReturn("ocid1.user.oc1..mnopqrstuvw");

            OracleCloudCredentials credentials = new OracleCloudCredentials();
            credentials.load(getSingleProfileConfiguration(), null);
            credentials.loadFromEnvironment();

            assertEquals("user", "ocid1.user.oc1..mnopqrstuvw", credentials.getUser());
            assertEquals("tenancy", "ocid1.tenancy.oc1..abcdefghijk", credentials.getTenancy());
            assertEquals("region", "eu-paris-1", credentials.getRegion());
            assertEquals("keyfile", "target/test-classes/keystores/privatekey.pkcs8.pem", credentials.getKeyfile());
            assertEquals("fingerprint", "97:a2:2f:f5:e8:39:d3:44:b7:63:f2:4e:31:18:a6:62", credentials.getFingerprint());
            assertEquals("pass phrase", "password", credentials.getPassphrase());
        }
    }

    @Test
    public void testGetDefault() throws Exception {
        OracleCloudCredentials credentials = OracleCloudCredentials.getDefault();
        assertNotNull("credentials", credentials);
    }

    @Test
    public void testGetDefaultProfile() {
        assertEquals("profile", "DEFAULT", OracleCloudCredentials.getDefaultProfile());

        try (MockedStatic<?> mock = mockStatic(OracleCloudCredentials.class, CALLS_REAL_METHODS)) {
            when(OracleCloudCredentials.getenv("OCI_CLI_PROFILE")).thenReturn("TEST");

            assertEquals("profile", "TEST", OracleCloudCredentials.getDefaultProfile());
        }
    }

    @Test
    public void testGetConfigFile() {
        assertEquals("config file", new File(System.getProperty("user.home") + "/.oci/config").getAbsolutePath(), OracleCloudCredentials.getConfigFile().getAbsolutePath());

        try (MockedStatic<?> mock = mockStatic(OracleCloudCredentials.class, CALLS_REAL_METHODS)) {
            when(OracleCloudCredentials.getenv("OCI_CLI_CONFIG_FILE")).thenReturn(".oci/config");

            assertEquals("config file", new File(".oci/config").getAbsolutePath(), OracleCloudCredentials.getConfigFile().getAbsolutePath());
        }
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        File config = getSingleProfileConfiguration();

        OracleCloudCredentials credentials = new OracleCloudCredentials();
        credentials.load(config, null);

        assertNotNull("private key", credentials.getPrivateKey());
    }

    @Test
    public void testGetFingerprint() throws Exception {
        String configuration = "[DEFAULT]\n" +
                "user=ocid1.user.oc1..abcdefghijk\n" +
                "tenancy=ocid1.tenancy.oc1..abcdefghijk\n" +
                "region=eu-paris-1\n" +
                "key_file=target/test-classes/keystores/privatekey.pkcs1.pem\n" +
                "pass_phrase=password\n";

        File config = File.createTempFile("ociconfig", null);
        config.deleteOnExit();
        FileUtils.writeStringToFile(config, configuration, "UTF-8");

        OracleCloudCredentials credentials = new OracleCloudCredentials();
        credentials.load(config, null);

        assertEquals("fingerprint", "35:fb:e5:0c:da:16:99:c3:aa:89:f1:0b:a0:27:67:49", credentials.getFingerprint());
    }
}
