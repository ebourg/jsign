/*
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

public class Zip64EndOfCentralDirectoryRecordTest {

    @Test
    public void testRead() throws Exception {
        File file = new File("target/test-classes/minimal.zip");

        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            channel.position(0x26E9);

            Zip64EndOfCentralDirectoryRecord record = new Zip64EndOfCentralDirectoryRecord();
            record.read(channel);

            assertEquals("version made by / file attributes compatibility", 0 /* DOS */, record.versionMadeBy >> 8);
            assertEquals("version made by / zip specification", 45, record.versionMadeBy & 0xFF);
            assertEquals("version needed to extract", 45, record.versionNeededToExtract);
            assertEquals("number of this disk", 0, record.numberOfThisDisk);
            assertEquals("number of the disk with the start of the central directory", 0, record.numberOfTheDiskWithTheStartOfTheCentralDirectory);
            assertEquals("number of entries in the central directory on this disk", 7, record.numberOfEntriesOnThisDisk);
            assertEquals("number of entries in the central directory", 7, record.numberOfEntries);
            assertEquals("central directory size", 622, record.centralDirectorySize);
            assertEquals("central directory offset", 0x247B, record.centralDirectoryOffset);
            assertArrayEquals("extensible data sector", new byte[0], record.extensibleDataSector);
        }
    }

    @Test
    public void testReadWrongRecord() throws Exception {
        File file = new File("target/test-classes/minimal.zip");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            Exception e = assertThrows(IOException.class, () -> new Zip64EndOfCentralDirectoryRecord().read(channel));
            assertEquals("message", "Invalid ZIP64 End of Central Directory Record signature 0x4034b50", e.getMessage());
        }
    }
}
