/**
 * Copyright 2012 Emmanuel Bourg
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
import java.security.Permission;
import java.util.List;

import junit.framework.TestCase;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.pe.PEFile;

public class PESignerCLITest extends TestCase {

    private PESignerCLI cli;
    private File sourceFile = new File("target/test-classes/wineyes.exe");
    private File targetFile = new File("target/test-classes/wineyes-signed-with-cli.exe");
    
    private String keystore = "keystore.jks";
    private String alias    = "test";
    private String keypass  = "password";

    private static final long SOURCE_FILE_CRC32 = 0xA6A363D8L;

    protected void setUp() throws Exception {
        cli = new PESignerCLI();
        
        // remove the files signed previously
        if (targetFile.exists()) {
            assertTrue("Unable to remove the previously signed file", targetFile.delete());
        }
        
        assertEquals("Source file CRC32", SOURCE_FILE_CRC32, FileUtils.checksumCRC32(sourceFile));
        Thread.sleep(100);
        FileUtils.copyFile(sourceFile, targetFile);
    }

    public void testPrintHelp() throws Exception {
        PESignerCLI.main("--help");
    }

    public void testMissingKeyStore() {
        try {
            cli.execute("" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testUnsupportedKeyStoreType() {
        try {
            cli.execute("--keystore=keystore.jks", "--storetype=ABC", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testKeyStoreNotFound() {
        try {
            cli.execute("--keystore=keystore2.jks", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testCorruptedKeyStore() {
        try {
            cli.execute("--keystore=" + targetFile, "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testMissingAlias() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testAliasNotFound() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "--alias=unknown", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testCertificateNotFound() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "--alias=foo", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testMissingFile() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "--alias=test", "--keypass=password");
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testFileNotFound() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "--alias=test", "--keypass=password", "wineyes-foo.exe");
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testCorruptedFile() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "--alias=test", "--keypass=password", "target/test-classes/keystore.jks");
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testConflictingAttributes() {
        try {
            cli.execute("--keystore=target/test-classes/keystore.jks", "--alias=test", "--keypass=password", "--keyfile=privatekey.pvk", "--certfile=certificate.spc", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testMissingCertFile() {
        try {
            cli.execute("--keyfile=target/test-classes/privatekey.pvk", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testMissingKeyFile() {
        try {
            cli.execute("--certfile=target/test-classes/certificate.spc", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testCertFileNotFound() {
        try {
            cli.execute("--certfile=target/test-classes/certificate2.spc", "--keyfile=target/test-classes/privatekey.pvk", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testKeyFileNotFound() {
        try {
            cli.execute("--certfile=target/test-classes/certificate.spc", "--keyfile=target/test-classes/privatekey2.pvk", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testCorruptedCertFile() {
        try {
            cli.execute("--certfile=target/test-classes/privatekey.pvk", "--keyfile=target/test-classes/privatekey.pvk", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testCorruptedKeyFile() {
        try {
            cli.execute("--certfile=target/test-classes/certificate.spc", "--keyfile=target/test-classes/certificate.spc", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testUnsupportedDigestAlgorithm() {
        try {
            cli.execute("--alg=SHA-123", "--keystore=target/test-classes/keystore.jks", "--alias=test", "--keypass=password", "" + targetFile);
            fail("No exception thrown");
        } catch (SignerException e) {
            // expected
        }
    }

    public void testSigning() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-1", "--keystore=target/test-classes/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "" + targetFile);

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        }
    }

    public void testSigningPKCS12() throws Exception {
        cli.execute("--name=WinEyes", "--url=http://www.steelblue.com/WinEyes", "--alg=SHA-256", "--keystore=target/test-classes/keystore.p12", "--alias=test", "--storepass=password", "" + targetFile);
        
        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        }
    }

    public void testSigningPVKSPC() throws Exception {
        cli.execute("--certfile=target/test-classes/certificate.spc", "--keyfile=target/test-classes/privatekey-encrypted.pvk", "--keypass=password", "" + targetFile);
        
        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        }
    }
    
    public void testTimestampingAuthenticode() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-cli-authenticode.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--tsaurl=http://timestamp.comodoca.com/authenticode", "--tsmode=authenticode", "" + targetFile2);
        
        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile2)) {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());
            
            CMSSignedData signature = signatures.get(0);
            
            assertNotNull(signature);
        }
    }

    public void testTimestampingRFC3161() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-cli-rfc3161.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--tsaurl=http://timestamp.comodoca.com/rfc3161", "--tsmode=rfc3161", "" + targetFile2);

        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile2)) {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        }
    }

    public void testReplaceSignature() throws Exception {
        File targetFile2 = new File("target/test-classes/wineyes-re-signed.exe");
        FileUtils.copyFile(sourceFile, targetFile2);
        cli.execute("--keystore=target/test-classes/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "" + targetFile2);
        
        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));
        
        cli.execute("--keystore=target/test-classes/" + keystore, "--alias=" + alias, "--keypass=" + keypass, "--alg=SHA-512", "--replace", "" + targetFile2);
        
        try (PEFile peFile = new PEFile(targetFile2)) {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            assertNotNull(signatures.get(0));
            
            assertEquals("Digest algorithm", DigestAlgorithm.SHA512.oid, signatures.get(0).getDigestAlgorithmIDs().iterator().next().getAlgorithm());
        }
    }

    public void testExitOnError() {
        NoExitSecurityManager manager = new NoExitSecurityManager();
        System.setSecurityManager(manager);

        try {
            PESignerCLI.main("foo.exe");
            fail("VM not terminated");
        } catch (SecurityException e) {
            // expected
            assertEquals("Exit code", Integer.valueOf(1), manager.getStatus());
        } finally {
            System.setSecurityManager(null);
        }
    }

    private static class NoExitSecurityManager extends SecurityManager {
        private Integer status;

        public Integer getStatus() {
            return status;
        }

        public void checkPermission(Permission perm) { }
        
        public void checkPermission(Permission perm, Object context) { }

        public void checkExit(int status) {
            this.status = status;
            throw new SecurityException("Exit disabled");
        }
    }
}
