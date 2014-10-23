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
import java.util.List;

import junit.framework.TestCase;
import net.jsign.pe.PEFile;
import org.apache.commons.io.FileUtils;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.DefaultLogger;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.ProjectHelper;
import org.bouncycastle.cms.CMSSignedData;

public class PESignerTaskTest extends TestCase {

    private Project project;

    protected void setUp() throws Exception {
        project = new Project();
        project.setCoreLoader(getClass().getClassLoader());
        project.init();

        File buildFile = new File("target/test-classes/testbuild.xml");
        project.setBaseDir(buildFile.getParentFile());

        final ProjectHelper helper = ProjectHelper.getProjectHelper();
        helper.parse(project, buildFile);

        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-signed-with-ant.exe");

        // remove the files signed previously
        if (targetFile.exists()) {
            assertTrue("Unable to remove the previously signed file", targetFile.delete());
        }

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

    public void testMissingKeyStore() {
        try {
            project.executeTarget("missing-keystore");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testUnsupportedKeyStoreType() {
        try {
            project.executeTarget("unsupported-keystore");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testKeyStoreNotFound() {
        try {
            project.executeTarget("keystore-not-found");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testCorruptedKeyStore() {
        try {
            project.executeTarget("corrupted-keystore");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testMissingAlias() {
        try {
            project.executeTarget("missing-alias");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testAliasNotFound() {
        try {
            project.executeTarget("alias-not-found");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testCertificateNotFound() {
        try {
            project.executeTarget("certificate-not-found");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testMissingFile() {
        try {
            project.executeTarget("missing-file");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testFileNotFound() {
        try {
            project.executeTarget("file-not-found");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testCorruptedFile() {
        try {
            project.executeTarget("corrupted-file");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testInvalidTimestampingAuthority() {
        try {
            project.executeTarget("invalid-timestamping-authority");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testConflictingAttributes() {
        try {
            project.executeTarget("conflicting-attributes");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testMissingCertFile() {
        try {
            project.executeTarget("missing-certfile");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testMissingKeyFile() {
        try {
            project.executeTarget("missing-keyfile");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testCertFileNotFound() {
        try {
            project.executeTarget("certfile-not-found");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testKeyFileNotFound() {
        try {
            project.executeTarget("keyfile-not-found");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testCorruptedCertFile() {
        try {
            project.executeTarget("corrupted-certfile");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testCorruptedKeyFile() {
        try {
            project.executeTarget("corrupted-keyfile");
            fail("No exception thrown");
        } catch (BuildException e) {
            // expected
        }
    }

    public void testSigning() throws Exception {
        project.executeTarget("signing");

        PEFile peFile = new PEFile(new File("target/test-classes/wineyes-signed-with-ant.exe"));
        try {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        } finally {
            peFile.close();
        }
    }

    public void testSigningPKCS12() throws Exception {
        project.executeTarget("signing-pkcs12");

        PEFile peFile = new PEFile(new File("target/test-classes/wineyes-signed-with-ant.exe"));
        try {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        } finally {
            peFile.close();
        }
    }

    public void testSigningPVKSPC() throws Exception {
        project.executeTarget("signing-pvk-spc");

        PEFile peFile = new PEFile(new File("target/test-classes/wineyes-signed-with-ant.exe"));
        try {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        } finally {
            peFile.close();
        }
    }
    
    public void testTimestamping() throws Exception {
        project.executeTarget("timestamping");

        PEFile peFile = new PEFile(new File("target/test-classes/wineyes-timestamped-with-ant.exe"));
        try {
            List<CMSSignedData> signatures = peFile.getSignatures();
            assertNotNull(signatures);
            assertEquals(1, signatures.size());

            CMSSignedData signature = signatures.get(0);

            assertNotNull(signature);
        } finally {
            peFile.close();
        }
    }
}
