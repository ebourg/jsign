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
import java.util.zip.CRC32;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.jca.Azure;
import net.jsign.jca.DigiCertONE;
import net.jsign.jca.GoogleCloud;
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
                .alias("Tomcat-PMC-cert-2021-04")
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
                .storepass("esigner_demo|esignerDemo#1")
                .keystore("https://cs-try.ssl.com")
                .keypass("RDXYgV9qju+6/7GnMf1vCbKexXVJmUVr+86Wq/8aIGg=")
                .alg("SHA-256");

        helper.sign(targetFile);

        SignatureAssert.assertSigned(new PEFile(targetFile), SHA256);
    }
}
