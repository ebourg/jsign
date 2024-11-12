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

public class Zip64EndOfCentralDirectoryLocatorTest {

    @Test
    public void testRead() throws Exception {
        File file = new File("target/test-classes/minimal.zip");

        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            channel.position(0x2721);

            Zip64EndOfCentralDirectoryLocator record = new Zip64EndOfCentralDirectoryLocator();
            record.read(channel);

            assertEquals("number of the disk with the start of the zip64 end of central directory", 0, record.numberOfTheDiskWithTheStartOfTheZip64EndOfCentralDirectory);
            assertEquals("relative offset of the zip64 end of central directory record", 0x26E9, record.zip64EndOfCentralDirectoryRecordOffset);
            assertEquals("number of disks", 1, record.numberOfDisks);
        }
    }

    @Test
    public void testReadWrongRecord() throws Exception {
        File file = new File("target/test-classes/minimal.zip");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            Exception e = assertThrows(IOException.class, () -> new Zip64EndOfCentralDirectoryLocator().read(channel));
            assertEquals("message", "Invalid ZIP64 End of Central Directory Locator signature 0x4034b50", e.getMessage());
        }
    }
}
