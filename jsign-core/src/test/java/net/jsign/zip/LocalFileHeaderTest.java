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

import static java.nio.charset.StandardCharsets.*;
import static org.junit.Assert.*;

public class LocalFileHeaderTest {

    @Test
    public void testRead() throws Exception {
        File file = new File("target/test-classes/minimal.msix");

        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            LocalFileHeader localFileHeader = new LocalFileHeader();
            localFileHeader.read(channel);

            assertEquals("version needed to extract", 45, localFileHeader.versionNeededToExtract);
            assertEquals("general purpose bit flag", 0b0000000000001110, localFileHeader.generalPurposeBitFlag);
            assertEquals("compression method", 8, localFileHeader.compressionMethod);
            assertEquals("last mod file time", 29469, localFileHeader.lastModFileTime);
            assertEquals("last mod file date", 22216, localFileHeader.lastModFileDate);
            assertEquals("crc-32", 0, localFileHeader.crc32);
            assertEquals("compressed size", 0, localFileHeader.compressedSize);
            assertEquals("uncompressed size", 0, localFileHeader.uncompressedSize);
            assertEquals("file name length", 12, localFileHeader.fileName.length);
            assertEquals("extra field length", 0, localFileHeader.extraField.length);
            assertEquals("file name", "Registry.dat", new String(localFileHeader.fileName, UTF_8));
        }
    }

    @Test
    public void testReadWrongRecord() {
        File file = new File("target/test-classes/minimal.msix");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            channel.position(1);
            new LocalFileHeader().read(channel);
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "Invalid Local File Header signature 0x2d04034b", e.getMessage());
        }
    }
}
