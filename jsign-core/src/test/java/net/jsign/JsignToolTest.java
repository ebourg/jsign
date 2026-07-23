/*
 * Copyright 2026 Emmanuel Bourg
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

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import static net.jsign.DigestAlgorithm.SHA256;
import static org.junit.Assert.assertTrue;

import net.jsign.pe.PEFile;
import net.jsign.timestamp.TimestampingMode;

public class JsignToolTest {

    @Test
    public void testTimestampRemoveAndShow() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-jsigntool-commands.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        JsignTool.sign()
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .storetype(KeyStoreType.JKS)
                .execute(targetFile);

        JsignTool.timestamp().tsmode(TimestampingMode.AUTHENTICODE).execute(targetFile);
        JsignTool.show().verbose(true).execute(targetFile);
        JsignTool.sign()
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .lazy()
                .detached()
                .execute(targetFile);
        JsignTool.remove().execute(targetFile);
    }

    @Test
    public void testSignTagAndExtractWithPaths() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile1 = new File("target/test-classes/wineyes-jsigntool-1.exe");
        File targetFile2 = new File("target/test-classes/wineyes-jsigntool-2.exe");

        FileUtils.copyFile(sourceFile, targetFile1);
        FileUtils.copyFile(sourceFile, targetFile2);

        JsignTool.sign()
                .keystore("target/test-classes/keystores/keystore.jks")
                .keypass("password")
                .execute(targetFile1, targetFile2);

        SignatureAssert.assertSigned(new PEFile(targetFile1), SHA256);
        SignatureAssert.assertSigned(new PEFile(targetFile2), SHA256);

        JsignTool.tag()
                .value("userid:1234-ABCD-5678-EFGH")
                .execute(targetFile1);

        JsignTool.extract()
                .format("PEM")
                .execute(targetFile1);

        assertTrue(new File("target/test-classes/wineyes-jsigntool-1.exe.sig.pem").exists());
    }
}
