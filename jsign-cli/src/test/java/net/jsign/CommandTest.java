/**
 * Copyright 2025 Emmanuel Bourg
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
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class CommandTest {

    @Parameters(name = "File #{index}: {0}")
    public static String[] files() {
        return new String[]{
                "target/test-classes/wineyes.exe",
                "target/test-classes/minimal.msi",
                "target/test-classes/minimal.msix",
                "target/test-classes/minimal.appxbundle",
                "target/test-classes/minimal.navx",
                "target/test-classes/hello-world.js",
                "target/test-classes/hello-world.ps1",
                "target/test-classes/hello-world.ps1xml",
                "target/test-classes/hello-world.vbs",
                "target/test-classes/hello-world.wsf",
                "target/test-classes/cat/wineyes.cat",
                "target/test-classes/mscab/sample1.cab",
                "target/test-classes/mscab/sample2-disk1.cab",
                "target/test-classes/mscab/sample2-disk2.cab",
                "target/test-classes/mscab/sample3.cab",
                "target/test-classes/mscab/sample4.cab",
                "target/test-classes/nuget/minimal.1.0.0.nupkg",
        };
    }

    private JsignCLI cli;
    private final File sourceFile;

    public CommandTest(String sourceFile) {
        this.sourceFile = new File(sourceFile);
    }

    @Before
    public void setUp() {
        cli = new JsignCLI();
    }

    private File copy(File sourceFile, String suffix) throws IOException {
        String name = sourceFile.getName();
        int dot = name.lastIndexOf('.');
        String targetName = name.substring(0, dot) + suffix + name.substring(dot);
        File targetFile = new File(sourceFile.getParentFile(), targetName);
        FileUtils.copyFile(sourceFile, targetFile);
        return targetFile;
    }

    @Test
    public void testTag() throws Exception {
        File targetFile = copy(sourceFile, "-signed-tagged");

        cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--keypass=password", "" + targetFile);
        cli.execute("tag", "--value", "userid:1234-ABCD-5678-EFGH", "" + targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertSigned(signable, SHA256);

            CMSSignedData signature = signable.getSignatures().get(0);
            SignerInformation signerInfo = signature.getSignerInfos().getSigners().iterator().next();
            Attribute attribute = signerInfo.getUnsignedAttributes().get(AuthenticodeObjectIdentifiers.JSIGN_UNSIGNED_DATA_OBJID);
            assertNotNull("Unsigned attribute not found", attribute);
            assertEquals("Unsigned attribute value", "userid:1234-ABCD-5678-EFGH", attribute.getAttrValues().getObjectAt(0).toString());
        }
    }

    @Test
    public void testTimestamp() throws Exception {
        File targetFile = copy(sourceFile, "-signed-then-timestamped");

        cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--keypass=password", "" + targetFile);
        cli.execute("timestamp", "--tsaurl=http://rfc3161.ai.moda", "--tsmode=RFC3161", "" + targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertSigned(signable, SHA256);
            SignatureAssert.assertTimestamped("Invalid timestamp", signable.getSignatures().get(0));
        }
    }

    @Test
    public void testRemove() throws Exception {
        File targetFile = copy(sourceFile, "-signed-removed");

        cli.execute("--keystore=target/test-classes/keystores/keystore.jks", "--keypass=password", "" + targetFile);
        cli.execute("remove", "" + targetFile);

        try (Signable signable = Signable.of(targetFile)) {
            SignatureAssert.assertNotSigned(signable);
        }
    }
}
