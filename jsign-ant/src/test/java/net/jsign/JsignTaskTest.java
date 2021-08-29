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
import java.io.OutputStream;
import java.io.PrintStream;

import org.apache.commons.io.FileUtils;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.DefaultLogger;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.ProjectHelper;
import org.junit.Before;
import org.junit.Test;

import net.jsign.msi.MSIFile;
import net.jsign.pe.PEFile;
import net.jsign.script.PowerShellScript;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class JsignTaskTest {

    private Project project;
    
    private final File sourceFile = new File("target/test-classes/wineyes.exe");
    private final File targetFile = new File("target/test-classes/wineyes-signed-with-ant.exe");
    
    private static final long SOURCE_FILE_CRC32 = 0xA6A363D8L;

    @Before
    public void setUp() throws Exception {
        project = new Project();
        project.setCoreLoader(getClass().getClassLoader());
        project.init();

        File buildFile = new File("target/test-classes/testbuild.xml");
        project.setBaseDir(buildFile.getParentFile());

        final ProjectHelper helper = ProjectHelper.getProjectHelper();
        helper.parse(project, buildFile);

        // remove the files signed previously
        if (targetFile.exists()) {
            assertTrue("Unable to remove the previously signed file", targetFile.delete());
        }

        assertEquals("Source file CRC32", SOURCE_FILE_CRC32, FileUtils.checksumCRC32(sourceFile));
        Thread.sleep(100);
        
        FileUtils.copyFile(sourceFile, targetFile);

        redirectOutput(System.out);
    }

    /**
     * Redirects the Ant output to the specified stream.
     */
    private void redirectOutput(OutputStream out) {
        DefaultLogger logger = new DefaultLogger();
        logger.setOutputPrintStream(new PrintStream(out));
        logger.setMessageOutputLevel(Project.MSG_INFO);
        project.addBuildListener(logger);
    }

    @Test(expected = BuildException.class)
    public void testMissingKeyStore() {
        project.executeTarget("missing-keystore");
    }

    @Test(expected = BuildException.class)
    public void testUnsupportedKeyStoreType() {
        project.executeTarget("unsupported-keystore");
    }

    @Test(expected = BuildException.class)
    public void testKeyStoreNotFound() {
        project.executeTarget("keystore-not-found");
    }

    @Test(expected = BuildException.class)
    public void testCorruptedKeyStore() {
        project.executeTarget("corrupted-keystore");
    }

    @Test(expected = BuildException.class)
    public void testMissingAlias() {
        project.executeTarget("missing-alias");
    }

    @Test(expected = BuildException.class)
    public void testAliasNotFound() {
        project.executeTarget("alias-not-found");
    }

    @Test(expected = BuildException.class)
    public void testCertificateNotFound() {
        project.executeTarget("certificate-not-found");
    }

    @Test(expected = BuildException.class)
    public void testMissingFile() {
        project.executeTarget("missing-file");
    }

    @Test(expected = BuildException.class)
    public void testFileNotFound() {
        project.executeTarget("file-not-found");
    }

    @Test(expected = BuildException.class)
    public void testCorruptedFile() {
        project.executeTarget("corrupted-file");
    }

    @Test(expected = BuildException.class)
    public void testConflictingAttributes() {
        project.executeTarget("conflicting-attributes");
    }

    @Test(expected = BuildException.class)
    public void testMissingCertFile() {
        project.executeTarget("missing-certfile");
    }

    @Test(expected = BuildException.class)
    public void testMissingKeyFile() {
        project.executeTarget("missing-keyfile");
    }

    @Test(expected = BuildException.class)
    public void testCertFileNotFound() {
        project.executeTarget("certfile-not-found");
    }

    @Test(expected = BuildException.class)
    public void testKeyFileNotFound() {
        project.executeTarget("keyfile-not-found");
    }

    @Test(expected = BuildException.class)
    public void testCorruptedCertFile() {
        project.executeTarget("corrupted-certfile");
    }

    @Test(expected = BuildException.class)
    public void testCorruptedKeyFile() {
        project.executeTarget("corrupted-keyfile");
    }

    @Test(expected = BuildException.class)
    public void testUnsupportedDigestAlgorithm() {
        project.executeTarget("unsupported-digest-algorithm");
    }

    @Test
    public void testSigning() throws Exception {
        project.executeTarget("signing");
        
        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA1);
        }
    }

    @Test
    public void testSigningMultipleFiles() throws Exception {
        FileUtils.copyFile(sourceFile, targetFile);

        project.executeTarget("signing-multiple-files");

        File targetFile2 = new File("target/test-classes/wineyes-multiple-files-test.exe");

        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));
        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA1);
        }
        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA1);
        }
    }

    @Test
    public void testSigningPowerShell() throws Exception {
        File sourceFile = new File("target/test-classes/hello-world.ps1");
        File targetFile = new File("target/test-classes/hello-world-signed-with-ant.ps1");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        project.executeTarget("signing-powershell");
        
        PowerShellScript script = new PowerShellScript(targetFile);

        SignatureAssert.assertSigned(script, SHA1);
    }

    @Test
    public void testSigningMSI() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.msi");
        File targetFile = new File("target/test-classes/minimal-signed-with-ant.msi");
        
        FileUtils.copyFile(sourceFile, targetFile);
        
        project.executeTarget("signing-msi");
        
        try (MSIFile file = new MSIFile(targetFile)) {
            SignatureAssert.assertSigned(file, SHA1);
        }
    }

    @Test
    public void testSigningPKCS12() throws Exception {
        project.executeTarget("signing-pkcs12");
        
        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testSigningPVKSPC() throws Exception {
        project.executeTarget("signing-pvk-spc");
        
        assertTrue("The file " + targetFile + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile));

        try (PEFile peFile = new PEFile(targetFile)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testTimestampingAuthenticode() throws Exception {
        project.executeTarget("timestamping-authenticode");
        
        File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-ant-authenticode.exe");
        
        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testTimestampingRFC3161() throws Exception {
        project.executeTarget("timestamping-rfc3161");
        
        File targetFile2 = new File("target/test-classes/wineyes-timestamped-with-ant-rfc3161.exe");
        
        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));

        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA256);
        }
    }

    @Test
    public void testReplaceSignature() throws Exception {
        project.executeTarget("replace-signature");
        
        File targetFile2 = new File("target/test-classes/wineyes-re-signed.exe");
        
        assertTrue("The file " + targetFile2 + " wasn't changed", SOURCE_FILE_CRC32 != FileUtils.checksumCRC32(targetFile2));
        
        try (PEFile peFile = new PEFile(targetFile2)) {
            SignatureAssert.assertSigned(peFile, SHA512);
        }
    }

    @Test
    public void testDetachedSignature() throws Exception {
        project.executeTarget("detach-signature");

        assertTrue("Signature wasn't detached", new File("target/test-classes/wineyes-signed-detached.exe.sig").exists());
    }
}
