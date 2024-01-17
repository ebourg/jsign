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

package net.jsign.appx;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

import static java.nio.ByteOrder.*;

/**
 * Local File Header:
 *
 * <pre>
 * local file header signature     4 bytes  (0x04034b50)
 * version needed to extract       2 bytes
 * general purpose bit flag        2 bytes
 * compression method              2 bytes
 * last mod file time              2 bytes
 * last mod file date              2 bytes
 * crc-32                          4 bytes
 * compressed size                 4 bytes
 * uncompressed size               4 bytes
 * file name length                2 bytes
 * extra field length              2 bytes
 * </pre>
 *
 * @since 6.0
 */
class LocalFileHeader extends ZipRecord {

    public static final int SIGNATURE = 0x04034b50;
    private static final int MIN_SIZE = 30;

    public int versionNeededToExtract;
    public int generalPurposeBitFlag;
    public int compressionMethod;
    public int lastModFileTime;
    public int lastModFileDate;
    public int crc32;
    public long compressedSize;
    public long uncompressedSize;
    public byte[] fileName = new byte[0];
    public byte[] extraField = new byte[0];

    @Override
    public void read(ReadableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();
        if (buffer.remaining() < MIN_SIZE) {
            throw new IOException("Invalid Local File Header");
        }

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid Local File Header signature " + String.format("0x%04x", signature & 0xFFFFFFFFL));
        }
        versionNeededToExtract = buffer.getShort();
        generalPurposeBitFlag = buffer.getShort();
        compressionMethod = buffer.getShort();
        lastModFileTime = buffer.getShort();
        lastModFileDate = buffer.getShort();
        crc32 = buffer.getInt();
        compressedSize = buffer.getInt() & 0xFFFFFFFFL;
        uncompressedSize = buffer.getInt() & 0xFFFFFFFFL;
        int fileNameLength = buffer.getShort() & 0xFFFF;
        int extraFieldsLength = buffer.getShort() & 0xFFFF;
        if (fileNameLength > 0) {
            fileName = new byte[fileNameLength];
            channel.read(ByteBuffer.wrap(fileName));
        }
        if (extraFieldsLength > 0) {
            byte[] extraFields = new byte[extraFieldsLength];
            channel.read(ByteBuffer.wrap(extraFields));
        }
    }

    @Override
    public ByteBuffer toBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE + fileName.length + extraField.length).order(LITTLE_ENDIAN);
        buffer.putInt(SIGNATURE);
        buffer.putShort((short) versionNeededToExtract);
        buffer.putShort((short) generalPurposeBitFlag);
        buffer.putShort((short) compressionMethod);
        buffer.putShort((short) lastModFileTime);
        buffer.putShort((short) lastModFileDate);
        buffer.putInt(crc32);
        buffer.putInt((int) compressedSize);
        buffer.putInt((int) uncompressedSize);
        buffer.putShort((short) fileName.length);
        buffer.putShort((short) extraField.length);
        buffer.put(fileName);
        buffer.put(extraField);
        buffer.flip();

        return buffer;
    }
}
