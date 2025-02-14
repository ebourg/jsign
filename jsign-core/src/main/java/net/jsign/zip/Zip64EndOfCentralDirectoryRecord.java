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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

import static java.nio.ByteOrder.*;

/**
 * ZIP64 End of Central Directory Record:
 *
 * <pre>
 * zip64 end of central directory signature                                       4 bytes  (0x06064b50)
 * size of zip64 end of central directory record                                  8 bytes
 * version made by                                                                2 bytes
 * version needed to extract                                                      2 bytes
 * number of this disk                                                            4 bytes
 * number of the disk with the start of the central directory                     4 bytes
 * total number of entries in the central directory on this disk                  8 bytes
 * total number of entries in the central directory                               8 bytes
 * size of the central directory                                                  8 bytes
 * offset of start of central directory with respect to the starting disk number  8 bytes
 * zip64 extensible data sector                                                   (variable size)
 * </pre>
 *
 * @since 6.0
 */
class Zip64EndOfCentralDirectoryRecord extends ZipRecord {

    public static final int SIGNATURE = 0x06064b50;
    private static final int MIN_SIZE = 56;

    public int versionMadeBy = 45;
    public int versionNeededToExtract = 45;
    public int numberOfThisDisk;
    public int numberOfTheDiskWithTheStartOfTheCentralDirectory;
    public long numberOfEntriesOnThisDisk;
    public long numberOfEntries;
    public long centralDirectorySize;
    public long centralDirectoryOffset;
    public byte[] extensibleDataSector = new byte[0];

    @Override
    public void read(ReadableByteChannel channel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE).order(LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();
        if (buffer.remaining() < MIN_SIZE) {
            throw new IOException("Invalid ZIP64 End of Central Directory Record");
        }

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid ZIP64 End of Central Directory Record signature " + String.format("0x%04x", signature & 0xFFFFFFFFL));
        }
        long sizeOfZip64EndOfCentralDirectoryRecord = buffer.getLong();
        versionMadeBy = buffer.getShort();
        versionNeededToExtract = buffer.getShort();
        numberOfThisDisk = buffer.getInt();
        numberOfTheDiskWithTheStartOfTheCentralDirectory = buffer.getInt();
        numberOfEntriesOnThisDisk = buffer.getLong();
        numberOfEntries = buffer.getLong();
        centralDirectorySize = buffer.getLong();
        centralDirectoryOffset = buffer.getLong();

        long recordSize = sizeOfZip64EndOfCentralDirectoryRecord + 4 /* signature */ + 8 /* size */;
        int extensibleDataSectorSize = (int) (recordSize - MIN_SIZE);
        if (extensibleDataSectorSize > 1024 * 1024) {
            throw new IOException("The extensible data sector of the ZIP64 End of Central Directory Record is too large (" + extensibleDataSectorSize + " bytes)");
        }
        if (extensibleDataSectorSize > 0) {
            extensibleDataSector = new byte[extensibleDataSectorSize];
            channel.read(ByteBuffer.wrap(extensibleDataSector));
        }
    }

    @Override
    public ByteBuffer toBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(MIN_SIZE + extensibleDataSector.length).order(LITTLE_ENDIAN);
        buffer.putInt(SIGNATURE);
        long sizeOfZip64EndOfCentralDirectoryRecord = extensibleDataSector.length + MIN_SIZE - 4 /* signature */ - 8 /* size */;
        buffer.putLong(sizeOfZip64EndOfCentralDirectoryRecord);
        buffer.putShort((short) versionMadeBy);
        buffer.putShort((short) versionNeededToExtract);
        buffer.putInt(numberOfThisDisk);
        buffer.putInt(numberOfTheDiskWithTheStartOfTheCentralDirectory);
        buffer.putLong(numberOfEntriesOnThisDisk);
        buffer.putLong(numberOfEntries);
        buffer.putLong(centralDirectorySize);
        buffer.putLong(centralDirectoryOffset);
        buffer.put(extensibleDataSector);
        buffer.flip();

        return buffer;
    }
}
