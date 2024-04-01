/**
 * Copyright 2021 Emmanuel Bourg
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
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.zip.CRC32;

import org.apache.commons.io.FileUtils;
import org.junit.Assume;
import org.junit.Test;

import net.jsign.jca.AWS;
import net.jsign.jca.Azure;
import net.jsign.jca.DigiCertONE;
import net.jsign.jca.GoogleCloud;
import net.jsign.jca.OracleCloudCredentials;
import net.jsign.jca.PIVCardTest;
import net.jsign.pe.PEFile;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class SignerHelperTest {

    @Test
    public void testDetachedSignature() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-detached.exe");

        File detachedSignatureFile = new File("target/test-classes/wineyes-signed-detached.exe.sig");
        detachedSignatureFile.delete();

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        // sign and detach
        signer.sign(targetFile);

        assertFalse("Signature was detached", detachedSignatureFile.exists());

        signer.alg("SHA-512").detached(true);
        signer.sign(targetFile);

        assertTrue("Signature wasn't detached", detachedSignatureFile.exists());

        // attach the signature
        File targetFile2 = new File("target/test-classes/wineyes-signed-attached.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        File detachedSignatureFile2 = new File("target/test-classes/wineyes-signed-attached.exe.sig");
        detachedSignatureFile2.delete();
        detachedSignatureFile.renameTo(detachedSignatureFile2);

        signer = new SignerHelper(new StdOutConsole(2), "parameter").detached(true);
        signer.sign(targetFile2);

        assertEquals(FileUtils.checksum(targetFile, new CRC32()).getValue(), FileUtils.checksum(targetFile2, new CRC32()).getValue());
    }

    @Test
    public void testDetachedSignatureWithNotPaddedFile() throws Exception {
        File origFile = new File("target/test-classes/wineyes.exe");
        File sourceFile = new File("target/test-classes/wineyes-notpadded.exe");

        FileUtils.copyFile(origFile, sourceFile);

        // make the test file not padded on a 8 byte boundary
        SeekableByteChannel channel = Files.newByteChannel(sourceFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE);
        channel.truncate(channel.size() - 3);
        channel.close();

        File targetFile = new File("target/test-classes/wineyes-notpadded-signed-detached.exe");

        File detachedSignatureFile = new File("target/test-classes/wineyes-notpadded-signed-detached.exe.sig");
        detachedSignatureFile.delete();

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .detached(true);

        // sign and detach
        signer.sign(targetFile);

        assertTrue("Signature wasn't detached", detachedSignatureFile.exists());

        // attach the signature
        File targetFile2 = new File("target/test-classes/wineyes-notpadded-signed-attached.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        File detachedSignatureFile2 = new File("target/test-classes/wineyes-notpadded-signed-attached.exe.sig");
        detachedSignatureFile2.delete();
        detachedSignatureFile.renameTo(detachedSignatureFile2);

        signer = new SignerHelper(new StdOutConsole(2), "parameter").detached(true);
        signer.sign(targetFile2);

        assertEquals(FileUtils.checksum(targetFile, new CRC32()).getValue(), FileUtils.checksum(targetFile2, new CRC32()).getValue());
    }

    @Test
    public void testPasswordFromFile() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        Files.write(new File("target/test-classes/storepass.txt").toPath(), "password".getBytes());

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("file:target/test-classes/storepass.txt");

        signer.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testPasswordFromFileFailed() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("file:/path/to/missing/file");

        try {
            signer.sign(targetFile);
        } catch (SignerException e) {
            assertEquals("message", "Failed to read the keypass parameter from the file '/path/to/missing/file'", e.getMessage());
        }
    }

    @Test
    public void testPasswordFromEnvironment() throws Exception {
        Assume.assumeTrue("STOREPASS environment variable not defined", System.getenv().containsKey("STOREPASS"));

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("env:STOREPASS");

        signer.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testPasswordFromEnvironmentFailed() throws Exception {
        Assume.assumeFalse(System.getenv().containsKey("MISSING_VAR"));

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("env:MISSING_VAR");

        try {
            signer.sign(targetFile);
        } catch (SignerException e) {
            assertEquals("message", "Failed to read the keypass parameter, the 'MISSING_VAR' environment variable is not defined", e.getMessage());
        }
    }

    @Test
    public void testAWS() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-aws.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("AWS")
                .keystore("eu-west-3")
                .storepass(AWS.getAccessKey() + "|" + AWS.getSecretKey())
                .alias("jsign")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testAzureKeyVault() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("AZUREKEYVAULT")
                .keystore("jsigntestkeyvault")
                .storepass(Azure.getAccessToken())
                .alias("jsign")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testGoogleCloud() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("GOOGLECLOUD")
                .keystore("projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring")
                .storepass(GoogleCloud.getAccessToken())
                .alias("test")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain-reversed.pem")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testDigiCertONE() throws Exception {
        String apikey = DigiCertONE.getApiKey();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("DIGICERTONE")
                .storepass(apikey + "|" + DigiCertONE.getClientCertificateFile() + "|" + DigiCertONE.getClientCertificatePassword())
                .alias("Tomcat-PMC-cert-2021-11")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testESigner() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("ESIGNER")
                .keystore("https://cs-try.ssl.com")
                .storepass("esigner_demo|esignerDemo#1")
                .alias("8b072e22-7685-4771-b5c6-48e46614915f")
                .keypass("RDXYgV9qju+6/7GnMf1vCbKexXVJmUVr+86Wq/8aIGg=")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testOracleCloud() throws Exception {
        Assume.assumeTrue("OCI configuration not found", OracleCloudCredentials.getConfigFile().exists());

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-oci.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("ORACLECLOUD")
                .alias("ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testPIV() throws Exception {
        PIVCardTest.assumeCardPresent();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-piv.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper(new StdOutConsole(1), "option")
                .storetype("PIV")
                .keystore("Yubikey")
                .storepass("123456")
                .alias("SIGNATURE")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testSignWithMismatchedKeyAlgorithms() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatched-keys.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keyfile("target/test-classes/keystores/privatekey-ec-p384.pkcs1.pem")
                .keypass("password")
                .certfile("target/test-classes/keystores/jsign-test-certificate-full-chain.pem");

        try {
            signer.sign(targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            assertEquals("message", "Signature verification failed, the private key doesn't match the certificate", e.getCause().getMessage());
        }

        SignatureAssert.assertSigned(Signable.of(targetFile));
    }

    @Test
    public void testSignWithMismatchedKeyLengths() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatched-keys.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keyfile("target/test-classes/keystores/privatekey.pkcs1.pem")
                .keypass("password")
                .certfile("target/test-classes/keystores/jsign-root-ca.pem");

        try {
            signer.sign(targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            assertEquals("message", "Signature verification failed, the certificate is a root or intermediate CA certificate (CN=Jsign Root Certificate Authority 2022)", e.getCause().getMessage());
        }

        SignatureAssert.assertSigned(Signable.of(targetFile));
    }

    @Test
    public void testSignWithMismatchedRSAKeys() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatched-keys.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter")
                .keyfile("target/test-classes/keystores/privatekey.pkcs1.pem")
                .keypass("password")
                .certfile("target/test-classes/keystores/jsign-test-certificate-partial-chain.pem");

        try {
            signer.sign(targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            assertEquals("message", "Signature verification failed, the certificate is a root or intermediate CA certificate (CN=Jsign Code Signing CA 2022)", e.getCause().getMessage());
        }

        SignatureAssert.assertSigned(Signable.of(targetFile));
    }

    @Test
    public void testMissingPKCS12KeyStorePassword() {
        SignerHelper signer = new SignerHelper(new StdOutConsole(2), "parameter");
        signer.keystore("target/test-classes/keystores/keystore.p12");
        signer.alias("test");
        try {
            signer.sign("target/test-classes/wineyes.exe");
        } catch (SignerException e) {
            assertEquals("message", "The keystore password must be specified", e.getMessage());
        }
    }
}
