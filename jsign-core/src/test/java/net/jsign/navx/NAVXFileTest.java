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

package net.jsign.navx;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

import org.apache.commons.io.FileUtils;
import org.junit.Assume;
import org.junit.Test;

import net.jsign.WindowsReadOnlyFileLock;

import static org.junit.Assert.*;

public class NAVXFileTest {

    @Test
    public void testIsNAVXFile() throws Exception {
        assertTrue(NAVXFile.isNAVXFile(new File("target/test-classes/minimal.navx")));
        assertFalse(NAVXFile.isNAVXFile(new File("target/test-classes/wineyes.exe")));
        assertFalse(NAVXFile.isNAVXFile(new File("target")));
        assertFalse(NAVXFile.isNAVXFile(new File("target/non-existent")));
    }

    @Test
    public void testIsNAVXFileWithLockedFile() throws Exception {
        Assume.assumeTrue(System.getProperty("os.name").contains("Windows"));

        File srcFile = new File("target/test-classes/minimal.navx");
        File destFile = new File("target/test-classes/minimal-locked.navx");
        FileUtils.copyFile(srcFile, destFile);

        try (WindowsReadOnlyFileLock lock = new WindowsReadOnlyFileLock(destFile)) {
            lock.lock();
            assertTrue(NAVXFile.isNAVXFile(destFile));
        }
    }

    @Test
    public void testInvalidContentSizeInHeader() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.navx");
        File targetFile = new File("target/test-classes/minimal-invalid-size.navx");

        Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

        try (RandomAccessFile file = new RandomAccessFile(targetFile, "rw")) {
            file.seek(28);
            file.writeInt(Integer.reverseBytes((int) targetFile.length()));
        }

        Exception e = assertThrows(IOException.class, () -> new NAVXFile(targetFile));
        assertEquals("message", "NAVX file is corrupt: invalid size in the header", e.getMessage());
    }

    @Test
    public void testInvalidTrailingSignatureInHeader() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.navx");
        File targetFile = new File("target/test-classes/minimal-invalid-trailing-signature.navx");

        Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

        try (RandomAccessFile file = new RandomAccessFile(targetFile, "rw")) {
            file.seek(36);
            file.writeInt(Integer.reverseBytes(0x12345678));
        }

        Exception e = assertThrows(IOException.class, () -> new NAVXFile(targetFile));
        assertEquals("message", "Invalid NAVX header signature", e.getMessage());
    }

    @Test
    public void testInvalidSignatureBlock() throws Exception {
        File sourceFile = new File("target/test-classes/minimal.navx");
        File targetFile = new File("target/test-classes/minimal-invalid-signature-block.navx");

        Files.copy(sourceFile.toPath(), targetFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

        try (RandomAccessFile file = new RandomAccessFile(targetFile, "rw")) {
            file.seek(targetFile.length());
            file.writeBytes("ABCD");
        }

        Exception e = assertThrows(IOException.class, () -> {
            try (NAVXFile navxFile = new NAVXFile(targetFile)) {
                navxFile.getSignatures();
            }
        });
        assertEquals("message", "Invalid NAVX signature block", e.getMessage());
    }
}
