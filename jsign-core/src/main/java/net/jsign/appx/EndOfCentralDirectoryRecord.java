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
import java.nio.channels.SeekableByteChannel;

import static java.nio.ByteOrder.*;

/**
 * End of Central Directory Record:
 *
 * <pre>
 * end of central directory signature                                                  4 bytes  (0x06054b50)
 * number of this disk                                                           2 bytes
 * number of the disk with the start of the central directory                    2 bytes
 * total number of entries in the central directory on this disk                 2 bytes
 * total number of entries in the central directory                              2 bytes
 * size of the central directory                                                 4 bytes
 * offset of start of central directory with respect to the starting disk number 4 bytes
 * .ZIP file comment length                                                      2 bytes
 * .ZIP file comment                                                             (variable size)
 * </pre>
 *
 * @since 5.1
 */
class EndOfCentralDirectoryRecord extends ZipRecord {

    public static final int SIGNATURE = 0x06054b50;
    private static final int MIN_SIZE = 22;
    private static final int MAX_SIZE = MIN_SIZE + 0xFFFF; // size with max comment length

    public int numberOfThisDisk;
    public int numberOfTheDiskWithTheStartOfTheCentralDirectory;
    public int numberOfEntriesOnThisDisk;
    public int numberOfEntries;
    public int centralDirectorySize;
    public int centralDirectoryOffset;
    public byte[] comment = new byte[0];

    public void load(SeekableByteChannel channel) throws IOException {
        if (!locate(channel)) {
            throw new IOException("End of Central Directory Record not found");
        }
        long position = channel.position();
        read(channel);
        channel.position(position);
    }

    public void read(ReadableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid End of Central Directory Record signature " + String.format("0x%04x", signature & 0xFFFFFFFFL));
        }
        numberOfThisDisk = buffer.getShort();
        numberOfTheDiskWithTheStartOfTheCentralDirectory = buffer.getShort();
        numberOfEntriesOnThisDisk = buffer.getShort();
        numberOfEntries = buffer.getShort();
        centralDirectorySize = buffer.getInt();
        centralDirectoryOffset = buffer.getInt();
        int commentLength = buffer.getShort();
        if (commentLength > 0) {
            comment = new byte[commentLength];
            channel.read(ByteBuffer.wrap(comment));
        }
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE + comment.length).order(LITTLE_ENDIAN);
        buffer.putInt(SIGNATURE);
        buffer.putShort((short) numberOfThisDisk);
        buffer.putShort((short) numberOfTheDiskWithTheStartOfTheCentralDirectory);
        buffer.putShort((short) numberOfEntriesOnThisDisk);
        buffer.putShort((short) numberOfEntries);
        buffer.putInt(centralDirectorySize);
        buffer.putInt(centralDirectoryOffset);
        buffer.putShort((short) comment.length);
        buffer.put(comment);
        buffer.flip();

        return buffer;
    }

    /**
     * Locates the End of Central Directory Record by searching the archive backwards.
     */
    public boolean locate(SeekableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES).order(LITTLE_ENDIAN);
        long minOffset = Math.max(0L, channel.size() - MAX_SIZE);
        long maxOffset = channel.size() - MIN_SIZE;

        for (long offset = maxOffset; offset >= minOffset; offset--) {
            channel.position(offset);
            channel.read(buffer);
            buffer.flip();
            if (buffer.getInt() == SIGNATURE) {
                channel.position(offset);
                return true;
            }
            buffer.rewind();
        }

        return false;
    }
}
