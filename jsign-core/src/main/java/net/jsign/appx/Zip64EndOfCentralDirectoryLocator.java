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
 * ZIP64 End of Central Directory Locator:
 *
 * <pre>
 * zip64 end of central dir locator signature                               4 bytes  (0x07064b50)
 * number of the disk with the start of the zip64 end of central directory  4 bytes
 * relative offset of the zip64 end of central directory record             8 bytes
 * total number of disks                                                    4 bytes
 * </pre>
 *
 * @since 5.1
 */
class Zip64EndOfCentralDirectoryLocator extends ZipRecord {

    public static final int SIGNATURE = 0x07064b50;
    public static final int SIZE = 20;

    public int numberOfTheDiskWithTheStartOfTheZip64EndOfCentralDirectory;
    public long zip64EndOfCentralDirectoryRecordOffset;
    public int numberOfDisks = 1;

    @Override
    public void read(ReadableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(SIZE).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid ZIP64 End of Central Directory Locator signature " + String.format("0x%04x", signature & 0xFFFFFFFFL));
        }
        numberOfTheDiskWithTheStartOfTheZip64EndOfCentralDirectory = buffer.getInt();
        zip64EndOfCentralDirectoryRecordOffset = buffer.getLong();
        numberOfDisks = buffer.getInt();
    }

    @Override
    public ByteBuffer toBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(SIZE).order(LITTLE_ENDIAN);
        buffer.putInt(SIGNATURE);
        buffer.putInt(numberOfTheDiskWithTheStartOfTheZip64EndOfCentralDirectory);
        buffer.putLong(zip64EndOfCentralDirectoryRecordOffset);
        buffer.putInt(numberOfDisks);
        buffer.flip();

        return buffer;
    }
}
