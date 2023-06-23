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

package net.jsign.appx;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import net.jsign.DigestAlgorithm;

import static java.nio.charset.StandardCharsets.*;
import static org.junit.Assert.*;

public class APPXFileTest {

    @Test
    public void testGetSignaturesFromUnsignedPackage() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.msix"))) {
            assertTrue("signature found", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testGetSignaturesFromSignedPackage() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal-signed-by-signtool.msix"))) {
            assertFalse("signature not found", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testAddContentType() throws Exception {
        File unsignedFile = new File("target/test-classes/minimal.msix");
        File modified = new File("target/test-classes/minimal-with-content-types-modified.msix");

        FileUtils.copyFile(unsignedFile, modified);

        // modify the content types
        try (APPXFile msix = new APPXFile(modified)) {
            msix.addContentType("/foo.txt", "text/foo");
            msix.addContentType("/foo.txt", "text/foo");
        }

        try (APPXFile msix = new APPXFile(modified)) {
            String contentTypes = new String(IOUtils.toByteArray(msix.getInputStream("[Content_Types].xml")), UTF_8);
            assertTrue("missing content type", contentTypes.contains("<Override PartName=\"/foo.txt\" ContentType=\"text/foo\"/>"));
            assertEquals("number of content types added", 1, StringUtils.countMatches(contentTypes, "text/foo"));
        }
    }

    @Test
    public void testGetRequiredDigestAlgorithm() throws Exception {
        try (APPXFile file = new APPXFile(new File("target/test-classes/minimal.msix"))) {
            assertEquals("digest algorithm", DigestAlgorithm.SHA256, file.getRequiredDigestAlgorithm());
        }
    }
}
