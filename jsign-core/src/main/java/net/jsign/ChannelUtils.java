/**
 * Copyright 2021 Emmanuel Bourg
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;

/**
 * Helper class for Channel operations.
 *
 * @since 4.0
 */
public class ChannelUtils {

    public static void copy(SeekableByteChannel src, WritableByteChannel dest) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024 * 1024);
        src.position(0);

        while (src.position() < src.size()) {
            buffer.clear();
            src.read(buffer);
            buffer.flip();
            dest.write(buffer);
        }
    }

    public static void copy(SeekableByteChannel src, SeekableByteChannel dest, long length) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024 * 1024);
        long remaining = length;
        long destOffset = dest.position();
        long srcOffset = src.position();
        while (remaining > 0) {
            int avail = (int) Math.min(remaining, buffer.capacity());
            buffer.clear();
            buffer.limit(avail);

            src.position(srcOffset);
            src.read(buffer);
            buffer.flip();

            dest.position(destOffset);
            dest.write(buffer);
            remaining -= buffer.position();
            srcOffset += buffer.position();
            destOffset += buffer.position();
        }
    }

    /**
     * Insert data into a SeekableByteChannel at the specified position,
     * shifting the data after the insertion point.
     */
    public static void insert(SeekableByteChannel channel, long position, byte[] data) throws IOException {
        if (position > channel.size()) {
            throw new IOException("Cannot insert data after the end of the file");
        }

        File backupFile = File.createTempFile("jsign", ".tmp");
        try (SeekableByteChannel backupChannel = Files.newByteChannel(backupFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            copy(channel, backupChannel);

            channel.position(position);
            channel.write(ByteBuffer.wrap(data));

            backupChannel.position(position);
            copy(backupChannel, channel, backupChannel.size() - position);
        } finally {
            backupFile.delete();
        }
    }

    /**
     * Update the specified digest by reading the SeekableByteChannel
     * from the start offset included to the end offset excluded.
     *
     * @param digest      the message digest to update
     * @param startOffset the start offset
     * @param endOffset   the end offset
     * @throws IOException if an I/O error occurs
     */
    public static void updateDigest(SeekableByteChannel channel, MessageDigest digest, long startOffset, long endOffset) throws IOException {
        channel.position(startOffset);

        ByteBuffer buffer = ByteBuffer.allocate(8192);

        long position = startOffset;
        while (position < endOffset) {
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), endOffset - position));
            channel.read(buffer);
            buffer.rewind();

            digest.update(buffer);

            position += buffer.limit();
        }
    }

    /**
     * Read a null terminated string from the specified channel.
     */
    public static byte[] readNullTerminatedString(ByteChannel channel) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte singleChar;
            ByteBuffer buffer = ByteBuffer.allocate(1);
            do {
                buffer.clear();
                buffer.limit(1);
                channel.read(buffer);
                buffer.flip();
                singleChar = buffer.array()[0];
                bos.write(singleChar);
            } while (singleChar != 0);
            return bos.toByteArray();
        }
    }
}
