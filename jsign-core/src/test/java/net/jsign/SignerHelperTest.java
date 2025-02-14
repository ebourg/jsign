/*
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
import java.util.logging.Logger;
import java.util.zip.CRC32;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.Assume;
import org.junit.Test;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.jca.AWS;
import net.jsign.jca.Azure;
import net.jsign.jca.DigiCertONE;
import net.jsign.jca.GoogleCloud;
import net.jsign.jca.OracleCloudCredentials;
import net.jsign.jca.PIVCardTest;
import net.jsign.pe.PEFile;
import net.jsign.timestamp.TimestampingMode;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

public class SignerHelperTest {

    static {
        Logger.getLogger("net.jsign").setUseParentHandlers(false);
        Logger.getLogger("net.jsign").addHandler(new StdOutLogHandler());
    }

    @Test
    public void testDetachedSignature() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-detached.exe");

        File detachedSignatureFile = new File("target/test-classes/wineyes-signed-detached.exe.sig");
        detachedSignatureFile.delete();

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        // sign and detach
        signer.execute(targetFile);

        assertFalse("Signature was detached", detachedSignatureFile.exists());

        signer.alg("SHA-512").detached(true);
        signer.execute(targetFile);

        assertTrue("Signature wasn't detached", detachedSignatureFile.exists());

        // attach the signature
        File targetFile2 = new File("target/test-classes/wineyes-signed-attached.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        File detachedSignatureFile2 = new File("target/test-classes/wineyes-signed-attached.exe.sig");
        detachedSignatureFile2.delete();
        detachedSignatureFile.renameTo(detachedSignatureFile2);

        signer = new SignerHelper("parameter").detached(true);
        signer.execute(targetFile2);

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

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .detached(true);

        // sign and detach
        signer.execute(targetFile);

        assertTrue("Signature wasn't detached", detachedSignatureFile.exists());

        // attach the signature
        File targetFile2 = new File("target/test-classes/wineyes-notpadded-signed-attached.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        File detachedSignatureFile2 = new File("target/test-classes/wineyes-notpadded-signed-attached.exe.sig");
        detachedSignatureFile2.delete();
        detachedSignatureFile.renameTo(detachedSignatureFile2);

        signer = new SignerHelper("parameter").detached(true);
        signer.execute(targetFile2);

        assertEquals(FileUtils.checksum(targetFile, new CRC32()).getValue(), FileUtils.checksum(targetFile2, new CRC32()).getValue());
    }

    @Test
    public void testPasswordFromFile() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        Files.write(new File("target/test-classes/storepass.txt").toPath(), "password".getBytes());

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("file:target/test-classes/storepass.txt");

        signer.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testPasswordFromFileFailed() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("file:/path/to/missing/file");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Failed to read the keypass parameter from the file '/path/to/missing/file'", e.getMessage());
    }

    @Test
    public void testPasswordFromEnvironment() throws Exception {
        Assume.assumeTrue("STOREPASS environment variable not defined", System.getenv().containsKey("STOREPASS"));

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("env:STOREPASS");

        signer.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testPasswordFromEnvironmentFailed() throws Exception {
        Assume.assumeFalse(System.getenv().containsKey("MISSING_VAR"));

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-external-password.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("env:MISSING_VAR");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Failed to read the keypass parameter, the 'MISSING_VAR' environment variable is not defined", e.getMessage());
    }

    @Test
    public void testAWS() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-aws.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("AWS")
                .keystore("eu-west-3")
                .storepass(AWS.getAccessKey() + "|" + AWS.getSecretKey())
                .alias("jsign")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testAzureKeyVault() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("AZUREKEYVAULT")
                .keystore("jsignvault")
                .storepass(Azure.getAccessToken())
                .alias("jsign")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testGoogleCloud() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("GOOGLECLOUD")
                .keystore("projects/fifth-glider-316809/locations/global/keyRings/jsignkeyring")
                .storepass(GoogleCloud.getAccessToken())
                .alias("test")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain-reversed.pem")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testDigiCertONE() throws Exception {
        String apikey = DigiCertONE.getApiKey();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("DIGICERTONE")
                .storepass(apikey + "|" + DigiCertONE.getClientCertificateFile() + "|" + DigiCertONE.getClientCertificatePassword())
                .alias("Tomcat-PMC-cert-2021-11")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testESigner() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signing-service.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("ESIGNER")
                .keystore("https://cs-try.ssl.com")
                .storepass("esigner_demo|esignerDemo#1")
                .alias("8b072e22-7685-4771-b5c6-48e46614915f")
                .keypass("RDXYgV9qju+6/7GnMf1vCbKexXVJmUVr+86Wq/8aIGg=")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testOracleCloud() throws Exception {
        Assume.assumeTrue("OCI configuration not found", OracleCloudCredentials.getConfigFile().exists());

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-oci.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("ORACLECLOUD")
                .alias("ocid1.key.oc1.eu-paris-1.h5tafwboaahxq.abrwiljrwkhgllb5zfqchmvdkmqnzutqeq5pz7yo6z7yhl2zyn2yncwzxiza")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testTrustedSigning() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-azure-trusted-signing.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("TRUSTEDSIGNING")
                .keystore("weu.codesigning.azure.net")
                .storepass(Azure.getAccessToken("https://codesigning.azure.net"))
                .alias("MyAccount/MyProfile")
                .alg("SHA-256");

        helper.sign(targetFile);

        Signable signable = Signable.of(targetFile);
        SignatureAssert.assertSigned(signable, SHA256);
        SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(0));
    }

    @Test
    public void testSignPath() throws Exception {
        String organization = System.getenv("SIGNPATH_ORGANIZATION_ID");
        String accessToken = System.getenv("SIGNPATH_API_TOKEN");
        assumeNotNull("SIGNPATH_ORGANIZATION_ID environment variable not defined", organization);
        assumeNotNull("SIGNPATH_API_TOKEN environment variable not defined", accessToken);

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-signpath.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("SIGNPATH")
                .keystore(organization)
                .storepass(accessToken)
                .alias("jsign/rsa-2048")
                .alg("SHA-256");

        helper.sign(targetFile);

        Signable signable = Signable.of(targetFile);
        SignatureAssert.assertSigned(signable, SHA256);
    }

    @Test
    public void testPIV() throws Exception {
        PIVCardTest.assumeCardPresent();

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-piv.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper helper = new SignerHelper("option")
                .storetype("PIV")
                .keystore("Yubikey")
                .storepass("123456")
                .alias("SIGNATURE")
                .certfile("src/test/resources/keystores/jsign-test-certificate-full-chain.pem")
                .alg("SHA-256");

        helper.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }

    @Test
    public void testSignWithMismatchedKeyAlgorithms() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatched-keys.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keyfile("target/test-classes/keystores/privatekey-ec-p384.pkcs1.pem")
                .keypass("password")
                .certfile("target/test-classes/keystores/jsign-test-certificate-full-chain.pem");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Signature verification failed, the private key doesn't match the certificate", e.getCause().getMessage());

        SignatureAssert.assertSigned(Signable.of(targetFile));
    }

    @Test
    public void testSignWithMismatchedKeyLengths() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatched-keys.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keyfile("target/test-classes/keystores/privatekey.pkcs1.pem")
                .keypass("password")
                .certfile("target/test-classes/keystores/jsign-root-ca.pem");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Signature verification failed, the certificate is a root or intermediate CA certificate (CN=Jsign Root Certificate Authority 2024)", e.getCause().getMessage());

        SignatureAssert.assertSigned(Signable.of(targetFile));
    }

    @Test
    public void testSignWithMismatchedRSAKeys() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-mismatched-keys.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keyfile("target/test-classes/keystores/privatekey.pkcs1.pem")
                .keypass("password")
                .certfile("target/test-classes/keystores/jsign-test-certificate-partial-chain.pem");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Signature verification failed, the certificate is a root or intermediate CA certificate (CN=Jsign Code Signing CA 2024)", e.getCause().getMessage());

        SignatureAssert.assertSigned(Signable.of(targetFile));
    }

    @Test
    public void testMissingPKCS12KeyStorePassword() {
        SignerHelper signer = new SignerHelper("parameter");
        signer.keystore("target/test-classes/keystores/keystore.p12");
        signer.alias("test");

        Exception e = assertThrows(SignerException.class, () -> signer.sign("target/test-classes/wineyes.exe"));
        assertEquals("message", "The keystore password must be specified", e.getMessage());
    }

    @Test
    public void testUnknownCommand() {
        SignerHelper signer = new SignerHelper("parameter");
        signer.command("unsign");

        Exception e = assertThrows(SignerException.class, () -> signer.execute("target/test-classes/wineyes.exe"));
        assertEquals("message", "Unknown command 'unsign'", e.getMessage());
    }

    @Test
    public void testExtractDER() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("extract");
        signer.execute(targetFile);

        File signatureFile = new File("target/test-classes/wineyes-signed.exe.sig");
        assertTrue("Signature not extracted", signatureFile.exists());
    }

    @Test
    public void testExtractPEM() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("extract");
        signer.format("PEM");
        signer.execute(targetFile);

        File signatureFile = new File("target/test-classes/wineyes-signed.exe.sig.pem");
        assertTrue("Signature not extracted", signatureFile.exists());
    }

    @Test
    public void testExtractWithInvalidFormat() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("extract");
        signer.format("TXT");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Unknown output format 'TXT'", e.getMessage());
    }

    @Test
    public void testExtractFromUnsignedFile() {
        File file = new File("target/test-classes/wineyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("extract");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "No signature found in target/test-classes/wineyes.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testExtractFromMissingFile() {
        File file = new File("target/test-classes/xeyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("extract");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "Couldn't find target/test-classes/xeyes.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testRemove() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);

        signer.command("remove");
        signer.execute(targetFile);

        SignatureAssert.assertNotSigned(new PEFile(targetFile));
    }

    @Test
    public void testRemoveFromUnsignedFile() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("remove");
        signer.execute(targetFile);

        SignatureAssert.assertNotSigned(new PEFile(targetFile));
    }

    @Test
    public void testRemoveFromMissingFile() {
        File file = new File("target/test-classes/xeyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("remove");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "Couldn't find target/test-classes/xeyes.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testTagWithString() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-tagged.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("tag");
        signer.value("userid:1234-ABCD-5678-EFGH");
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            CMSSignedData signature = signable.getSignatures().get(0);
            SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
            Attribute attribute = signerInfo.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID);
            assertNotNull("Unsigned attribute not found", attribute);
            assertEquals("Unsigned attribute value", "userid:1234-ABCD-5678-EFGH", attribute.getAttrValues().getObjectAt(0).toString());
        }
    }

    @Test
    public void testTagWithBinaryData() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-tagged.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .tsaurl("http://timestamp.digicert.com");

        signer.execute(targetFile);

        signer.command("tag");
        signer.value("0x414243444546");
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            CMSSignedData signature = signable.getSignatures().get(0);
            SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
            Attribute attribute = signerInfo.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID);

            assertNotNull("Unsigned attribute not found", attribute);
            assertArrayEquals("Unsigned attribute value", "ABCDEF".getBytes(), ((DEROctetString) attribute.getAttrValues().getObjectAt(0)).getOctets());
        }
    }

    @Test
    public void testTagWithFileContent() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-tagged.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        File template = new File("target/test-classes/template.bin");
        Files.write(template.toPath(), "0123456".getBytes());

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("tag");
        signer.value("file:" + template.getAbsolutePath());
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            CMSSignedData signature = signable.getSignatures().get(0);
            SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
            Attribute attribute = signerInfo.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID);

            assertNotNull("Unsigned attribute not found", attribute);
            assertArrayEquals("Unsigned attribute value", "0123456".getBytes(), ((DEROctetString) attribute.getAttrValues().getObjectAt(0)).getOctets());
        }
    }

    @Test
    public void testTagWithMissingFile() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-tagged.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("tag");
        signer.value("file:missing-template.bin");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(targetFile));
        assertEquals("message", "Couldn't modify the signature of target/test-classes/wineyes-signed-tagged.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testTagWithDefaultTemplate() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-tagged.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);

        signer.command("tag");
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            CMSSignedData signature = signable.getSignatures().get(0);
            SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
            Attribute attribute = signerInfo.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID);

            assertNotNull("Unsigned attribute not found", attribute);

            String value = new String(((DEROctetString) attribute.getAttrValues().getObjectAt(0)).getOctets());
            assertTrue("Unsigned attribute value", value.startsWith("-----BEGIN TAG-----"));
            assertTrue("Unsigned attribute value", value.endsWith("-----END TAG-----"));
        }
    }

    @Test
    public void testTagUnsignedFile() {
        File file = new File("target/test-classes/wineyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("tag");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "No signature found in target/test-classes/wineyes.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testTagMissingFile() {
        File file = new File("target/test-classes/xeyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("tag");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "Couldn't find target/test-classes/xeyes.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testTimestamp() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-then-timestamped.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .tsmode(TimestampingMode.AUTHENTICODE.name());

        signer.execute(targetFile);

        signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password");

        signer.execute(targetFile);
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(0));
            SignatureAssert.assertNotTimestamped("Unexpected timestamp", signable.getSignatures().get(1));
            SignatureAssert.assertNotTimestamped("Unexpected timestamp", signable.getSignatures().get(2));
        }

        signer.command("timestamp");
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(0));
            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(1));
            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(2));
        }
    }

    @Test
    public void testReplaceTimestamp() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-timestamp-replaced.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        SignerHelper signer = new SignerHelper("parameter")
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .tsaurl("http://timestamp.sectigo.com")
                .tsmode(TimestampingMode.AUTHENTICODE.name());

        signer.execute(targetFile);
        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(0));
        }

        signer = new SignerHelper("parameter");
        signer.command("timestamp");
        signer.tsaurl("http://timestamp.sectigo.com");
        signer.tsmode(TimestampingMode.AUTHENTICODE.name());
        signer.replace(true);
        signer.execute(targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            CMSSignedData signature = signable.getSignatures().get(0);
            SignatureAssert.assertTimestamped("Invalid timestamp", signature);
            SignerInformation signerInformation = signature.getSignerInfos().iterator().next();
            assertNull("old timestamp not removed", signerInformation.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.SPC_RFC3161_OBJID));
            assertNotNull("missing new timestamp", signerInformation.getUnsignedAttributes().get(CMSAttributes.counterSignature));
        }
    }

    @Test
    public void testTimestampUnsignedFile() {
        File file = new File("target/test-classes/wineyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("timestamp");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "No signature found in target/test-classes/wineyes.exe", e.getMessage().replace('\\', '/'));
    }

    @Test
    public void testTimestampMissingFile() {
        File file = new File("target/test-classes/xeyes.exe");

        SignerHelper signer = new SignerHelper("parameter");
        signer.command("timestamp");

        Exception e = assertThrows(SignerException.class, () -> signer.execute(file));
        assertEquals("message", "Couldn't find target/test-classes/xeyes.exe", e.getMessage().replace('\\', '/'));
    }
}
