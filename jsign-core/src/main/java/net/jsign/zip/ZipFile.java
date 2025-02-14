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

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.apache.commons.io.input.BoundedInputStream;

import net.jsign.ChannelUtils;

import static java.nio.charset.StandardCharsets.*;

/**
 * Simplified implementation of the ZIP file format, just good enough to add an entry to an existing file.
 *
 * @since 6.0
 */
public class ZipFile implements Closeable {

    /** The channel used for in-memory signing */
    protected final SeekableByteChannel channel;

    protected CentralDirectory centralDirectory;

    /**
     * Create a ZipFile from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public ZipFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
    }

    /**
     * Create a ZipFile from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public ZipFile(SeekableByteChannel channel) throws IOException {
        this.channel = channel;
        centralDirectory = new CentralDirectory();
        centralDirectory.read(channel);
    }

    public InputStream getInputStream(String name) throws IOException {
        return getInputStream(name, -1);
    }

    public InputStream getInputStream(String name, int limit) throws IOException {
        CentralDirectoryFileHeader header = centralDirectory.entries.get(name);
        if (header == null) {
            throw new IOException("Entry not found: " + name);
        }
        if (limit != -1 && header.getUncompressedSize() > limit) {
            throw new IOException("The entry " + name + " is too large to be read (" + header.getUncompressedSize() + " bytes)");
        }
        channel.position(header.getLocalHeaderOffset());

        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.read(channel);
        InputStream in = Channels.newInputStream(channel);
        in = new BoundedInputStream(in, header.getCompressedSize());
        switch (header.compressionMethod) {
            case 0 /* STORED */:
                return in;
            case 8 /* DEFLATED */:
                Inflater inflater = new Inflater(true);
                return new InflaterInputStream(in, inflater);
            default:
                throw new IOException("Unsupported compression method " + header.compressionMethod + " for entry " + name);
        }
    }

    public void addEntry(String name, byte[] data, boolean compressed) throws IOException {
        // compute CRC32 of the uncompressed data
        CRC32 crc32 = new CRC32();
        crc32.update(data);

        int uncompressedSize = data.length;
        int compressedSize;

        if (compressed) {
            // deflate the data
            Deflater deflater = new Deflater(9, true);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DeflaterOutputStream dos = new DeflaterOutputStream(bos, deflater);
            dos.write(data);
            dos.flush();
            dos.close();

            data = bos.toByteArray();
            compressedSize = data.length;
        } else {
            compressedSize = uncompressedSize;
        }

        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.versionNeededToExtract = 20;
        localFileHeader.generalPurposeBitFlag = 0;
        localFileHeader.compressionMethod = compressed ? 8 : 0;
        localFileHeader.lastModFileTime = 0b00000_00000_00000; // 00:00:00
        localFileHeader.lastModFileDate = 0b0000000_0001_00001; // 1980-01-01
        localFileHeader.crc32 = (int) crc32.getValue();
        localFileHeader.compressedSize = compressedSize;
        localFileHeader.uncompressedSize = uncompressedSize;
        localFileHeader.fileName = name.getBytes(UTF_8);

        channel.position(centralDirectory.centralDirectoryOffset);
        long offset = channel.position();
        localFileHeader.write(channel);
        channel.write(ByteBuffer.wrap(data));

        boolean needsZip64 = offset > 0xFFFFFFFFL;

        CentralDirectoryFileHeader centralDirectoryFileHeader = new CentralDirectoryFileHeader();
        centralDirectoryFileHeader.versionMadeBy = 45;
        centralDirectoryFileHeader.versionNeededToExtract = 20;
        centralDirectoryFileHeader.generalPurposeBitFlag = localFileHeader.generalPurposeBitFlag;
        centralDirectoryFileHeader.compressionMethod = localFileHeader.compressionMethod;
        centralDirectoryFileHeader.lastModFileTime = localFileHeader.lastModFileTime;
        centralDirectoryFileHeader.lastModFileDate = localFileHeader.lastModFileDate;
        centralDirectoryFileHeader.crc32 = localFileHeader.crc32;
        centralDirectoryFileHeader.compressedSize = localFileHeader.compressedSize;
        centralDirectoryFileHeader.uncompressedSize = uncompressedSize;
        centralDirectoryFileHeader.diskNumberStart = 0;
        centralDirectoryFileHeader.internalFileAttributes = 0;
        centralDirectoryFileHeader.externalFileAttributes = 0;
        centralDirectoryFileHeader.localHeaderOffset = needsZip64 ? 0xFFFFFFFFL : offset;
        centralDirectoryFileHeader.fileName = localFileHeader.fileName;

        if (needsZip64) {
            Zip64ExtendedInfoExtraField zip64ExtraField = new Zip64ExtendedInfoExtraField(-1, -1, offset, -1);
            centralDirectoryFileHeader.extraFields.put(zip64ExtraField.id, zip64ExtraField);
        }

        centralDirectory.entries.put(name, centralDirectoryFileHeader);

        centralDirectory.write(channel);
    }

    public void renameEntry(String oldName, String newName) throws IOException {
        if (oldName.length() != newName.length()) {
            throw new IllegalArgumentException("The new name must have the same length");
        }
        CentralDirectoryFileHeader centralDirectoryFileHeader = centralDirectory.entries.get(oldName);
        centralDirectoryFileHeader.fileName = newName.getBytes(UTF_8);
        centralDirectory.entries.remove(oldName);
        centralDirectory.entries.put(newName, centralDirectoryFileHeader);

        long offset = centralDirectoryFileHeader.getLocalHeaderOffset();
        channel.position(offset);
        LocalFileHeader localFileHeader = new LocalFileHeader();
        localFileHeader.read(channel);
        localFileHeader.fileName = newName.getBytes(UTF_8);
        channel.position(offset);
        localFileHeader.write(channel);

        channel.position(centralDirectory.centralDirectoryOffset);
        centralDirectory.write(channel);
    }

    public void removeEntry(String name) throws IOException {
        CentralDirectoryFileHeader centralDirectoryFileHeader = centralDirectory.entries.get(name);
        ChannelUtils.delete(channel, centralDirectoryFileHeader.getLocalHeaderOffset(), centralDirectory.getEntrySize(name));

        centralDirectory.removeEntry(name);

        channel.position(centralDirectory.centralDirectoryOffset);
        centralDirectory.write(channel);
        channel.truncate(channel.position());
    }

    @Override
    public void close() throws IOException {
        if (channel != null) {
            channel.close();
        }
    }
}
