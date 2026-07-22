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

package net.jsign.cat;

import java.io.File;

import org.apache.commons.io.FileUtils;
import org.junit.Assume;
import org.junit.Test;

import net.jsign.WindowsReadOnlyFileLock;

import static org.junit.Assert.*;

public class CatalogFileTest {

    @Test
    public void testIsCatalogFile() {
        assertTrue(CatalogFile.isCatalogFile(new File("target/test-classes/cat/wineyes.cat")));
        assertFalse(CatalogFile.isCatalogFile(new File("target/test-classes/wineyes.exe")));
        assertFalse(CatalogFile.isCatalogFile(new File("target")));
        assertFalse(CatalogFile.isCatalogFile(new File("target/non-existent")));
    }

    @Test
    public void testIsCatalogFileWithLockedFile() throws Exception {
        Assume.assumeTrue(System.getProperty("os.name").contains("Windows"));

        File srcFile = new File("target/test-classes/cat/wineyes.cat");
        File destFile = new File("target/test-classes/cat/wineyes-locked.cat");
        FileUtils.copyFile(srcFile, destFile);

        try (WindowsReadOnlyFileLock lock = new WindowsReadOnlyFileLock(destFile)) {
            lock.lock();
            assertTrue(CatalogFile.isCatalogFile(destFile));
        }
    }
}
