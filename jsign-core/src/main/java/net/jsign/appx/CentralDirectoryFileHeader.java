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
import java.util.LinkedHashMap;
import java.util.Map;

import static java.nio.ByteOrder.*;

/**
 * Central Directory File Header:
 *
 * <pre>
 * central file header signature   4 bytes  (0x02014b50)
 * version made by                 2 bytes
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
 * file comment length             2 bytes
 * disk number start               2 bytes
 * internal file attributes        2 bytes
 * external file attributes        4 bytes
 * relative offset of local header 4 bytes
 *
 * file name (variable size)
 * extra field (variable size)
 * file comment (variable size)
 * </pre>
 *
 * @since 5.1
 */
class CentralDirectoryFileHeader extends ZipRecord {

    public static final int SIGNATURE = 0x02014b50;
    private static final int MIN_SIZE = 46;

    public int versionMadeBy;
    public int versionNeededToExtract;
    public int generalPurposeBitFlag;
    public int compressionMethod;
    public int lastModFileTime;
    public int lastModFileDate;
    public int crc32;
    public long compressedSize;
    public long uncompressedSize;
    public int diskNumberStart;
    public int internalFileAttributes;
    public int externalFileAttributes;
    public long localHeaderOffset;
    public byte[] fileName = new byte[0];
    public byte[] fileComment = new byte[0];

    public Map<Integer, ExtraField> extraFields = new LinkedHashMap<>();

    @Override
    public void read(ReadableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();
        if (buffer.remaining() < MIN_SIZE) {
            throw new IOException("Invalid Central Directory File Header");
        }

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid Central Directory File Header signature " + String.format("0x%04x", signature & 0xFFFFFFFFL));
        }
        versionMadeBy = buffer.getShort();
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
        int fileCommentLength = buffer.getShort() & 0xFFFF;
        diskNumberStart = buffer.getShort();
        internalFileAttributes = buffer.getShort();
        externalFileAttributes = buffer.getInt();
        localHeaderOffset = buffer.getInt() & 0xFFFFFFFFL;
        if (fileNameLength > 0) {
            fileName = new byte[fileNameLength];
            channel.read(ByteBuffer.wrap(fileName));
        }
        if (extraFieldsLength > 0) {
            byte[] extraFields = new byte[extraFieldsLength];
            channel.read(ByteBuffer.wrap(extraFields));

            this.extraFields = ExtraField.parseAll(ByteBuffer.wrap(extraFields).order(LITTLE_ENDIAN),
                    uncompressedSize == 0xFFFFFFFFL,
                    compressedSize == 0xFFFFFFFFL,
                    localHeaderOffset == 0xFFFFFFFFL,
                    diskNumberStart == 0xFFFF);
        }
        if (fileCommentLength > 0) {
            fileComment = new byte[fileCommentLength];
            channel.read(ByteBuffer.wrap(fileComment));
        }

        // validate the offset and sizes
        if (!extraFields.containsKey(1) && (localHeaderOffset == 0xFFFFFFFFL || compressedSize == 0xFFFFFFFFL || uncompressedSize == 0xFFFFFFFFL)) {
            throw new IOException("Missing ZIP64 extra field in the Central Directory File Header");
        }
    }

    private int getExtraFieldsLength() {
        int length = 0;
        for (ExtraField field : extraFields.values()) {
            length += field.size();
        }
        return length;
    }

    @Override
    public ByteBuffer toBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE + fileName.length + getExtraFieldsLength() + fileComment.length).order(LITTLE_ENDIAN);
        buffer.putInt(SIGNATURE);
        buffer.putShort((short) versionMadeBy);
        buffer.putShort((short) versionNeededToExtract);
        buffer.putShort((short) generalPurposeBitFlag);
        buffer.putShort((short) compressionMethod);
        buffer.putShort((short) lastModFileTime);
        buffer.putShort((short) lastModFileDate);
        buffer.putInt(crc32);
        buffer.putInt((int) compressedSize);
        buffer.putInt((int) uncompressedSize);
        buffer.putShort((short) fileName.length);
        buffer.putShort((short) getExtraFieldsLength());
        buffer.putShort((short) fileComment.length);
        buffer.putShort((short) diskNumberStart);
        buffer.putShort((short) internalFileAttributes);
        buffer.putInt(externalFileAttributes);
        buffer.putInt((int) localHeaderOffset);
        buffer.put(fileName);
        if (!extraFields.isEmpty()) {
            for (ExtraField field : extraFields.values()) {
                field.write(buffer);
            }
        }
        buffer.put(fileComment);
        buffer.flip();

        return buffer;
    }

    public long getCompressedSize() {
        if (compressedSize == 0xFFFFFFFFL) {
            Zip64ExtendedInfoExtraField zip64ExtraField = (Zip64ExtendedInfoExtraField) extraFields.get(1);
            return zip64ExtraField.compressedSize;
        } else {
            return compressedSize;
        }
    }

    public long getUncompressedSize() {
        if (uncompressedSize == 0xFFFFFFFFL) {
            Zip64ExtendedInfoExtraField zip64ExtraField = (Zip64ExtendedInfoExtraField) extraFields.get(1);
            return zip64ExtraField.uncompressedSize;
        } else {
            return uncompressedSize;
        }
    }

    public long getLocalHeaderOffset() {
        if (localHeaderOffset == 0xFFFFFFFFL) {
            Zip64ExtendedInfoExtraField zip64ExtraField = (Zip64ExtendedInfoExtraField) extraFields.get(1);
            return zip64ExtraField.localHeaderOffset;
        } else {
            return localHeaderOffset;
        }
    }
}
