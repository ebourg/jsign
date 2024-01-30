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
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

import org.junit.Test;

import static org.junit.Assert.*;

public class EndOfCentralDirectoryRecordTest {

    @Test
    public void testLocate() throws Exception {
        File file = new File("target/test-classes/minimal.msix");

        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            EndOfCentralDirectoryRecord record = new EndOfCentralDirectoryRecord();
            assertTrue("record not found", record.locate(channel));
            assertEquals("position", 0x2735, channel.position());
        }
    }

    @Test
    public void testLocateNotFound() throws Exception {
        File file = new File("target/test-classes/minimal.msi");

        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            EndOfCentralDirectoryRecord record = new EndOfCentralDirectoryRecord();
            assertFalse("record found", record.locate(channel));
        }
    }

    @Test
    public void testLoad() throws Exception {
        File file = new File("target/test-classes/minimal.msix");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            EndOfCentralDirectoryRecord record = new EndOfCentralDirectoryRecord();
            record.load(channel);

            assertEquals("number of this disks", -1, record.numberOfThisDisk);
            assertEquals("number of the disk with the start of the central directory", -1, record.numberOfTheDiskWithTheStartOfTheCentralDirectory);
            assertEquals("number of entries", -1, record.numberOfEntries);
            assertEquals("number of entries on this disk", -1, record.numberOfEntriesOnThisDisk);
            assertEquals("central directory size", -1, record.centralDirectorySize);
            assertEquals("central directory offset", -1, record.centralDirectoryOffset);
            assertArrayEquals("comment", new byte[0], record.comment);
        }
    }

    @Test
    public void testLoadInvalid() {
        File file = new File("target/test-classes/minimal.msi");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            EndOfCentralDirectoryRecord record = new EndOfCentralDirectoryRecord();
            record.load(channel);
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "End of Central Directory Record not found", e.getMessage());
        }
    }

    @Test
    public void testReadWrongRecord() {
        File file = new File("target/test-classes/minimal.msix");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            new EndOfCentralDirectoryRecord().read(channel);
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "Invalid End of Central Directory Record signature 0x4034b50", e.getMessage());
        }
    }
}
