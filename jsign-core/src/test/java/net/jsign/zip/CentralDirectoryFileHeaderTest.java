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

public class CentralDirectoryFileHeaderTest {

    @Test
    public void testRead() throws Exception {
        File file = new File("target/test-classes/minimal.zip");

        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            channel.position(0x247B);

            CentralDirectoryFileHeader centralDirectoryFileHeader = new CentralDirectoryFileHeader();
            centralDirectoryFileHeader.read(channel);

            assertEquals("version made by", 45, centralDirectoryFileHeader.versionMadeBy);
            assertEquals("version needed to extract", 45, centralDirectoryFileHeader.versionNeededToExtract);
            assertEquals("general purpose bit flag", 0b0000000000001110, centralDirectoryFileHeader.generalPurposeBitFlag);
            assertEquals("compression method", 8, centralDirectoryFileHeader.compressionMethod);
            assertEquals("last mod file time", 29469, centralDirectoryFileHeader.lastModFileTime);
            assertEquals("last mod file date", 22216, centralDirectoryFileHeader.lastModFileDate);
            assertEquals("crc-32", 0x2E799553, centralDirectoryFileHeader.crc32);
            assertEquals("compressed size", 0xFFFFFFFFL, centralDirectoryFileHeader.compressedSize);
            assertEquals("uncompressed size", 0xFFFFFFFFL, centralDirectoryFileHeader.uncompressedSize);
            assertEquals("disk number start", 0, centralDirectoryFileHeader.diskNumberStart);
            assertEquals("internal file attributes", 0, centralDirectoryFileHeader.internalFileAttributes);
            assertEquals("external file attributes", 0, centralDirectoryFileHeader.externalFileAttributes);
            assertEquals("local header offset", 0xFFFFFFFFL, centralDirectoryFileHeader.localHeaderOffset);
            assertEquals("file name length", 12, centralDirectoryFileHeader.fileName.length);
            assertEquals("extra fields", 1, centralDirectoryFileHeader.extraFields.size());
            assertEquals("file name", "Registry.dat", new String(centralDirectoryFileHeader.fileName, UTF_8));

            Zip64ExtendedInfoExtraField z64ExtraField = (Zip64ExtendedInfoExtraField) centralDirectoryFileHeader.extraFields.get(1);
            assertNotNull("zip64 extended info extra field not found", z64ExtraField);
            assertEquals("uncompressed size", 16384, z64ExtraField.uncompressedSize);
            assertEquals("compressed size", 2715, z64ExtraField.compressedSize);
            assertEquals("local header offset", 0, z64ExtraField.localHeaderOffset);
            assertEquals("disk number start", -1, z64ExtraField.diskNumberStart);
        }
    }

    @Test
    public void testReadWrongRecord() {
        File file = new File("target/test-classes/minimal.zip");
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            new CentralDirectoryFileHeader().read(channel);
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "Invalid Central Directory File Header signature 0x4034b50", e.getMessage());
        }
    }
}
