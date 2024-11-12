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

package net.jsign.zip;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.*;
import static org.junit.Assert.*;

public class ZipFileTest {

    @Test
    public void getGetInputStream() throws Exception {
        try (ZipFile file = new ZipFile(new File("target/test-classes/minimal.msix"))) {
            InputStream in = file.getInputStream("AppxManifest.xml");
            assertNotNull("input stream found", in);

            String content = IOUtils.toString(in, UTF_8);
            assertTrue(content.startsWith("\uFEFF<?xml"));
        }
    }

    @Test
    public void getGetInputStreamWithUnknownEntry() throws Exception {
        try (ZipFile file = new ZipFile(new File("target/test-classes/minimal.msix"))) {
            Exception e = assertThrows(IOException.class, () -> file.getInputStream("META-INF/MANIFEST.MF"));
            assertEquals("message", "Entry not found: META-INF/MANIFEST.MF", e.getMessage());
        }
    }

    @Test
    public void getGetInputStreamWithLimit() throws Exception {
        try (ZipFile file = new ZipFile(new File("target/test-classes/minimal.zip"))) {
            Exception e = assertThrows(IOException.class, () -> file.getInputStream("AppxManifest.xml", 128));
            assertEquals("message", "The entry AppxManifest.xml is too large to be read (1224 bytes)", e.getMessage());
        }
    }

    @Test
    public void testAddEntry() throws Exception {
        File original = new File("target/test-classes/minimal.msix");
        File modified = new File("target/test-classes/minimal-with-extra-entry.msix.zip");

        FileUtils.copyFile(original, modified);

        try (ZipFile file = new ZipFile(modified)) {
            file.addEntry("hello.txt", "Hello World!".getBytes(UTF_8), true);
        }

        try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(modified)) {
            assertNotNull(zip.getEntry("[Content_Types].xml"));
            assertNotNull(zip.getEntry("hello.txt"));
        }

        try (ZipFile file = new ZipFile(modified)) {
            InputStream in = file.getInputStream("hello.txt");
            assertEquals("Hello World!", IOUtils.toString(in, UTF_8));
        }
    }

    @Test
    public void testRenameEntry() throws Exception {
        File original = new File("target/test-classes/minimal.msix");
        File modified = new File("target/test-classes/minimal-with-entry-renamed.msix.zip");

        FileUtils.copyFile(original, modified);

        try (ZipFile file = new ZipFile(modified)) {
            file.renameEntry("[Content_Types].xml", "[Content_Types].old");
            assertFalse(file.centralDirectory.entries.containsKey("[Content_Types].xml"));
            assertTrue(file.centralDirectory.entries.containsKey("[Content_Types].old"));

            assertThrows(IllegalArgumentException.class, () -> file.renameEntry("[Content_Types].old", "[Content_Types].xml.old"));
        }

        try (ZipFile file = new ZipFile(modified)) {
            assertNull("old entry still present", file.centralDirectory.entries.get("[Content_Types].xml"));
            assertNotNull("new entry missing", file.centralDirectory.entries.get("[Content_Types].old"));
        }
    }

    @Test
    public void testRemoveEntry() throws Exception {
        File original = new File("target/test-classes/minimal.zip");
        File modified = new File("target/test-classes/minimal-with-entries-removed.zip");

        FileUtils.copyFile(original, modified);

        try (ZipFile file = new ZipFile(modified)) {
            // first entry
            file.removeEntry("Registry.dat");
            assertFalse(file.centralDirectory.entries.containsKey("Registry.dat"));

            // middle entry
            file.removeEntry("Resources.pri");
            assertFalse(file.centralDirectory.entries.containsKey("Resources.pri"));

            // last entry
            file.removeEntry("[Content_Types].xml");
            assertFalse(file.centralDirectory.entries.containsKey("[Content_Types].xml"));
        }

        try (java.util.zip.ZipFile file = new java.util.zip.ZipFile(modified)) {
            assertNull("Registry.dat entry not removed", file.getEntry("Registry.dat"));
            assertNull("Resources.pri entry not removed", file.getEntry("Resources.pri"));
            assertNull("[Content_Types].xml entry not removed", file.getEntry("[Content_Types].xml"));
        }
    }

    @Test
    public void testMultiVolumeArchive() throws Exception {
        File original = new File("target/test-classes/minimal.msix");
        File modified = new File("target/test-classes/minimal-multi-volume.msix.zip");

        FileUtils.copyFile(original, modified);

        // patch the file to make it a multi-volume archive
        try (SeekableByteChannel channel = Files.newByteChannel(modified.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long offset = channel.size() - 22;
            channel.position(offset);
            EndOfCentralDirectoryRecord record = new EndOfCentralDirectoryRecord();
            record.read(channel);

            record.numberOfThisDisk = 1;
            record.numberOfTheDiskWithTheStartOfTheCentralDirectory = 1;

            channel.position(offset);
            record.write(channel);
        }

        try (ZipFile file = new ZipFile(modified)) {
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "Multi-volume archives are not supported", e.getMessage());
        }
    }
}
