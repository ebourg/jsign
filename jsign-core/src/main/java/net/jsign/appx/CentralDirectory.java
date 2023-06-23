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
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Central directory of a ZIP file.
 *
 * @since 5.1
 */
class CentralDirectory {

    private final EndOfCentralDirectoryRecord endOfCentralDirectoryRecord = new EndOfCentralDirectoryRecord();
    private final Zip64EndOfCentralDirectoryLocator zip64EndOfCentralDirectoryLocator = new Zip64EndOfCentralDirectoryLocator();
    private final Zip64EndOfCentralDirectoryRecord zip64EndOfCentralDirectoryRecord = new Zip64EndOfCentralDirectoryRecord();

    /** The location of the central directory */
    public long centralDirectoryOffset = -1;

    /** The entries of the central directory */
    public Map<String, CentralDirectoryFileHeader> entries = new LinkedHashMap<>();

    public void read(SeekableByteChannel channel) throws IOException {
        endOfCentralDirectoryRecord.load(channel);
        if (endOfCentralDirectoryRecord.numberOfThisDisk > 0) {
            throw new IOException("Multi-volume archives are not supported");
        }

        long numberOfEntries;

        if (endOfCentralDirectoryRecord.centralDirectoryOffset == -1) {
            // look for the ZIP64 End of Central Directory Locator
            channel.position(channel.position() - Zip64EndOfCentralDirectoryLocator.SIZE);
            zip64EndOfCentralDirectoryLocator.read(channel);

            // read the ZIP64 End of Central Directory Record
            channel.position(zip64EndOfCentralDirectoryLocator.zip64EndOfCentralDirectoryRecordOffset);
            zip64EndOfCentralDirectoryRecord.read(channel);

            centralDirectoryOffset = zip64EndOfCentralDirectoryRecord.centralDirectoryOffset;
            numberOfEntries = (int) zip64EndOfCentralDirectoryRecord.numberOfEntries;
        } else {
            centralDirectoryOffset = endOfCentralDirectoryRecord.centralDirectoryOffset;
            numberOfEntries = endOfCentralDirectoryRecord.numberOfEntries;
        }

        // check if the offset is valid
        if (centralDirectoryOffset < 0 || centralDirectoryOffset > channel.size()) {
            throw new IOException("Invalid central directory offset: " + centralDirectoryOffset);
        }

        // read the entries
        channel.position(centralDirectoryOffset);
        for (int i = 0; i < numberOfEntries; i++) {
            CentralDirectoryFileHeader entry = new CentralDirectoryFileHeader();
            entry.read(channel);
            entries.put(new String(entry.fileName, StandardCharsets.ISO_8859_1), entry);
        }
    }

    /**
     * Write the central directory at the current position of the channel and update the offset.
     *
     * @param channel the channel to write to
     */
    public void write(SeekableByteChannel channel) throws IOException {
        long offset = channel.position();
        centralDirectoryOffset = offset;
        write(channel, offset);
    }

    /**
     * Write the central directory at the current position of the channel but don't update the offset.
     *
     * @param channel the channel to write to
     * @param offset the offset of the central directory written in the End of Central Directory Record
     */
    public void write(SeekableByteChannel channel, long offset) throws IOException {
        // write the entries
        long position = channel.position();
        for (CentralDirectoryFileHeader entry : entries.values()) {
            entry.write(channel);
        }

        long centralDirectorySize = channel.position() - position;

        // write the End of Central Directory Record
        if (endOfCentralDirectoryRecord.centralDirectoryOffset == -1 || offset > 0xFFFFFFFFL) {
            endOfCentralDirectoryRecord.centralDirectoryOffset = -1;
            endOfCentralDirectoryRecord.centralDirectorySize = -1;

            zip64EndOfCentralDirectoryRecord.numberOfEntriesOnThisDisk = entries.size();
            zip64EndOfCentralDirectoryRecord.numberOfEntries = entries.size();
            zip64EndOfCentralDirectoryRecord.centralDirectorySize = centralDirectorySize;
            zip64EndOfCentralDirectoryRecord.centralDirectoryOffset = offset;
            zip64EndOfCentralDirectoryRecord.write(channel);

            zip64EndOfCentralDirectoryLocator.zip64EndOfCentralDirectoryRecordOffset = offset + centralDirectorySize;
            zip64EndOfCentralDirectoryLocator.write(channel);

        } else {
            endOfCentralDirectoryRecord.numberOfEntriesOnThisDisk = entries.size();
            endOfCentralDirectoryRecord.numberOfEntries = entries.size();
            endOfCentralDirectoryRecord.centralDirectorySize = (int) centralDirectorySize;
            endOfCentralDirectoryRecord.centralDirectoryOffset = (int) offset;
        }

        endOfCentralDirectoryRecord.numberOfThisDisk = 0;
        endOfCentralDirectoryRecord.numberOfTheDiskWithTheStartOfTheCentralDirectory = 0;
        endOfCentralDirectoryRecord.write(channel);
    }
}
