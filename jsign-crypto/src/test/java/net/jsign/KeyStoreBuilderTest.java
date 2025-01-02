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

import net.jsign.jca.OpenPGPCardTest;
import net.jsign.jca.PIVCardTest;
import org.apache.commons.io.FileUtils;
import org.junit.Assume;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.ProviderException;

import static net.jsign.KeyStoreType.AWS;
import static net.jsign.KeyStoreType.AZUREKEYVAULT;
import static net.jsign.KeyStoreType.DIGICERTONE;
import static net.jsign.KeyStoreType.ESIGNER;
import static net.jsign.KeyStoreType.GARASIGN;
import static net.jsign.KeyStoreType.GOOGLECLOUD;
import static net.jsign.KeyStoreType.HASHICORPVAULT;
import static net.jsign.KeyStoreType.JCEKS;
import static net.jsign.KeyStoreType.JKS;
import static net.jsign.KeyStoreType.OPENPGP;
import static net.jsign.KeyStoreType.ORACLECLOUD;
import static net.jsign.KeyStoreType.PIV;
import static net.jsign.KeyStoreType.PKCS11;
import static net.jsign.KeyStoreType.PKCS12;
import static net.jsign.KeyStoreType.SIGNSERVER;
import static net.jsign.KeyStoreType.TRUSTEDSIGNING;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

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

        Exception e = assertThrows(IllegalArgumentException.class, builder::storepass);
        assertEquals("message", "Failed to read the storepass parameter, the 'MISSING_VAR' environment variable is not defined", e.getMessage());
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

        Exception e = assertThrows(IllegalArgumentException.class, builder::storepass);
        assertEquals("message", "Failed to read the storepass parameter from the file '/path/to/missing/file'", e.getMessage());
    }

    @Test
    public void testBuildAWS() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(AWS);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the AWS region", e.getMessage());

        builder.keystore("eu-west-1");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "certfile parameter must be set", e.getMessage());

        builder.certfile("keystores/jsign-test-certificate.pem");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertTrue("message", e.getMessage().matches(
                "storepass parameter must specify the AWS credentials\\: \\<accessKey\\>\\|\\<secretKey\\>\\[\\|\\<sessionToken\\>\\], when not running from an EC2 instance \\(.*\\)"));

        builder.storepass("<accessKey>|<secretKey>|<sessionToken>");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildAzureKeyVault() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(AZUREKEYVAULT);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the Azure vault name", e.getMessage());

        builder.keystore("jsigntestkeyvault");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the Azure API access token", e.getMessage());

        builder.storepass("0123456789ABCDEF");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildDigiCertONE() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(DIGICERTONE);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>", e.getMessage());

        builder.storepass("0123456789ABCDEF");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the DigiCert ONE API key and the client certificate: <apikey>|<keystore>|<password>", e.getMessage());

        builder.storepass("APIKEY|keystore.p12|password");

        e = assertThrows(RuntimeException.class, builder::build);
        assertEquals("message", "Failed to load the client certificate for DigiCert ONE", e.getMessage());

        builder.keystore("https://clientauth.demo.one.digicert.com");
        builder.storepass("APIKEY|target/test-classes/keystores/keystore.p12|password");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }


    @Test
    public void testBuildESigner() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(ESIGNER);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the SSL.com username and password: <username>|<password>", e.getMessage());

        builder.storepass("password");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the SSL.com username and password: <username>|<password>", e.getMessage());

        builder.storepass("esigner_test|esignerTest#1");

        e = assertThrows(IllegalStateException.class, builder::build);
        assertEquals("message", "Authentication failed with SSL.com", e.getMessage());

        builder.storepass("esigner_demo|esignerDemo#1");
        builder.keystore("https://cs-try.ssl.com");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildGoogleCloud() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(GOOGLECLOUD);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the Goole Cloud keyring", e.getMessage());

        builder.keystore("projects/first-rain-123/locations/global/keyRings/mykeyring/cryptoKeys/jsign");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the path of the keyring (projects/{projectName}/locations/{location}/keyRings/{keyringName})", e.getMessage());

        builder.keystore("projects/first-rain-123/locations/global/keyRings/mykeyring");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the Goole Cloud API access token", e.getMessage());

        builder.storepass("0123456789ABCDEF");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "certfile parameter must be set", e.getMessage());

        builder.certfile("keystores/jsign-test-certificate.pem");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildHashiCorpVault() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(HASHICORPVAULT);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the HashiCorp Vault secrets engine URL", e.getMessage());

        builder.keystore("https://vault.example.com:8200/v1/gcpkms/");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the HashiCorp Vault token", e.getMessage());

        builder.storepass("0123456789ABCDEF");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "certfile parameter must be set", e.getMessage());

        builder.certfile("keystores/jsign-test-certificate.pem");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildOracleCloud() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(ORACLECLOUD);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "certfile parameter must be set", e.getMessage());

        builder.certfile("keystores/jsign-test-certificate.pem");

        File config = File.createTempFile("ociconfig", null);
        config.deleteOnExit();
        FileUtils.writeStringToFile(config, "[DEFAULT]\n", "UTF-8");

        builder.storepass(config.getAbsolutePath() + "|DEFAULT");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildTrustedSigning() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(TRUSTEDSIGNING);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the Azure endpoint (<region>.codesigning.azure.net)", e.getMessage());

        builder.keystore("https://weu.codesigning.azure.net");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the Azure API access token", e.getMessage());

        builder.storepass("0123456789ABCDEF");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildGaraSign() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(GARASIGN);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the GaraSign username/password and/or the path to the keystore containing the TLS client certificate: <username>|<password>, <certificate>, or <username>|<password>|<certificate>", e.getMessage());

        builder.storepass("username|password|keystore.p12|storepass");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the GaraSign username/password and/or the path to the keystore containing the TLS client certificate: <username>|<password>, <certificate>, or <username>|<password>|<certificate>", e.getMessage());

        builder.storepass("username|password");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);

        builder = new KeyStoreBuilder().storetype(GARASIGN).keystore("https://api.garantir.io");
        builder.storepass("keystore.p12");

        keystore = builder.build();
        assertNotNull("keystore", keystore);

        builder = new KeyStoreBuilder().storetype(GARASIGN).keystore("https://api.garantir.io");
        builder.storepass("keystore.p12");
        builder.storepass("username|password|keystore.p12");
        builder.keypass("keypass");

        keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildSignServer() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(SIGNSERVER);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must specify the SignServer API endpoint (e.g. https://example.com/signserver/)", e.getMessage());

        builder.keystore("https://example.com/signserver");

        builder.storepass("username|password|certificate.p12");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the SignServer username/password or the path to the keystore containing the TLS client certificate: <username>|<password> or <certificate>", e.getMessage());

        builder.storepass("username|password");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);

        builder.storepass(null);

        keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildJKS() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(JKS);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must be set", e.getMessage());

        builder.keystore("target/test-classes/keystores/missing.jks");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "The keystore target/test-classes/keystores/missing.jks couldn't be found", e.getMessage());

        builder.keystore("target/test-classes/keystores/keystore.jks");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildJCEKS() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(JCEKS);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must be set", e.getMessage());

        builder.keystore("target/test-classes/keystores/missing.jceks");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "The keystore target/test-classes/keystores/missing.jceks couldn't be found", e.getMessage());

        builder.keystore("target/test-classes/keystores/keystore.jceks");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildPKCS12() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(PKCS12);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must be set", e.getMessage());

        builder.keystore("target/test-classes/keystores/missing.p12");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "The keystore target/test-classes/keystores/missing.p12 couldn't be found", e.getMessage());

        builder.keystore("target/test-classes/keystores/keystore.p12");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildWithoutStoreType() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder();

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "Either keystore, or keyfile and certfile, or storetype parameters must be set", e.getMessage());

        builder.keystore("target/test-classes/keystores/keystore.error");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "Keystore file 'target/test-classes/keystores/keystore.error' not found", e.getMessage());

        builder.keystore("target/test-classes/keystores/keystore.p12");

        assertThat("storetype", builder.storetype(), isA(Pkcs12KeyStore.class));

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildPKCS11() {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(PKCS11);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter must be set", e.getMessage());

        builder.keystore("target/test-classes/pkcs11-missing.cfg");

        e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "keystore parameter should either refer to the SunPKCS11 configuration file or to the name of the provider configured in jre/lib/security/java.security", e.getMessage());

        builder.keystore("target/test-classes/keystores/keystore.p12");

        e = assertThrows(ProviderException.class, builder::build);
        assertEquals("message", "Failed to create a SunPKCS11 provider from the configuration target/test-classes/keystores/keystore.p12", e.getMessage());
    }

    @Test
    public void testBuildOpenPGP() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(OPENPGP);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the PIN", e.getMessage());

        OpenPGPCardTest.assumeCardPresent();

        builder.storepass("123456");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testBuildPIV() throws Exception {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype(PIV);

        Exception e = assertThrows(IllegalArgumentException.class, builder::build);
        assertEquals("message", "storepass parameter must specify the PIN", e.getMessage());

        PIVCardTest.assumeCardPresent();

        builder.storepass("123456");

        KeyStore keystore = builder.build();
        assertNotNull("keystore", keystore);
    }

    @Test
    public void testLowerCaseStoreType() {
        KeyStoreBuilder builder = new KeyStoreBuilder().storetype("pkcs12");
        assertThat("storetype", builder.storetype(), isA(Pkcs12KeyStore.class));
    }

    @Test
    public void testGetType() {
        assertThat(KeyStoreBuilder.getType(new File("keystore.p12")), isA(Pkcs12KeyStore.class));
        assertThat(KeyStoreBuilder.getType(new File("keystore.pfx")), isA(Pkcs12KeyStore.class));
        assertThat(KeyStoreBuilder.getType(new File("keystore.jceks")), isA(JceKeyStore.class));
        assertThat(KeyStoreBuilder.getType(new File("keystore.jks")), isA(JavaKeyStore.class));
        assertNull(KeyStoreBuilder.getType(new File("keystore.unknown")));
    }

    @Test
    public void testGetTypePKCS12FromHeader() throws Exception {
        File source = new File("target/test-classes/keystores/keystore.p12");
        File target = new File("target/test-classes/keystores/keystore.p12.ext");
        FileUtils.copyFile(source, target);

        assertThat(KeyStoreBuilder.getType(target), isA(Pkcs12KeyStore.class));
    }

    @Test
    public void testGetTypeJCEKSFromHeader() throws Exception {
        File source = new File("target/test-classes/keystores/keystore.jceks");
        File target = new File("target/test-classes/keystores/keystore.jceks.ext");
        FileUtils.copyFile(source, target);

        assertThat(KeyStoreBuilder.getType(target), isA(JceKeyStore.class));
    }

    @Test
    public void testGetTypeJKSFromHeader() throws Exception {
        File source = new File("target/test-classes/keystores/keystore.jks");
        File target = new File("target/test-classes/keystores/keystore.jks.ext");
        FileUtils.copyFile(source, target);

        assertThat(KeyStoreBuilder.getType(target), isA(JavaKeyStore.class));
    }

    @Test
    public void testGetTypeUnknown() {
        assertNull(KeyStoreBuilder.getType(new File("target/test-classes/keystores/jsign-root-ca.pem")));
    }
}
