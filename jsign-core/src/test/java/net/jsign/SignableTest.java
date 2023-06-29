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

package net.jsign;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.appx.APPXFile;
import net.jsign.script.VBScript;

import static org.junit.Assert.*;

public class SignableTest {

    @Test
    public void testOfWithUnsupportedFormat() throws Exception {
        try (Signable signable = Signable.of(new File("pom.xml"))) {
            fail("Exception not thrown");
        } catch (UnsupportedOperationException e) {
            assertEquals("message", "Unsupported file: pom.xml", e.getMessage());
        }
    }

    @Test
    public void testOfWithMixedCaseExtension() throws Exception {
        FileUtils.copyFile(new File("target/test-classes/hello-world.vbs"), new File("target/test-classes/hello-world-renamed.VBS"));
        try (Signable signable = Signable.of(new File("target/test-classes/hello-world-renamed.VBS"))) {
            assertTrue(signable instanceof VBScript);
        }

        FileUtils.copyFile(new File("target/test-classes/minimal.msix"), new File("target/test-classes/minimal-renamed.AppxBundle"));
        try (Signable signable = Signable.of(new File("target/test-classes/minimal-renamed.AppxBundle"))) {
            assertTrue(signable instanceof APPXFile);
        }
    }
}
