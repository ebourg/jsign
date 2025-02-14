/*
 * Copyright 2019 Emmanuel Bourg
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

package net.jsign.msi;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.SignatureAssert.*;
import static org.junit.Assert.*;

public class MSIFileTest {

    @Test
    public void testIsMSIFile() throws Exception {
        assertFalse(MSIFile.isMSIFile(new File("pom.xml")));
        assertTrue(MSIFile.isMSIFile(new File("target/test-classes/minimal.msi")));

        // small file
        File file = File.createTempFile("small", ".msi");
        FileUtils.writeByteArrayToFile(file, new byte[3]);
        assertFalse(MSIFile.isMSIFile(file));
    }

    @Test
    public void testCloseTwice() throws Exception {
        MSIFile file = new MSIFile(new File("target/test-classes/minimal.msi"));
        file.close();
        file.close();
    }

    @Test
    public void testRemoveSignature() throws Exception {
        File sourceFile = new File("target/test-classes/minimal-signed-with-signtool.msi");
        File targetFile = new File("target/test-classes/minimal-unsigned.msi");

        FileUtils.copyFile(sourceFile, targetFile);

        try (MSIFile file = new MSIFile(targetFile)) {
            assertSigned(file, SHA1);
            file.setSignature(null);
            file.save();
            assertNotSigned(file);
        }
    }
}
