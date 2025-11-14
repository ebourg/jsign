/*
 * Copyright 2012 Emmanuel Bourg
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

package net.jsign.pe;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Entry of the data directory.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
class DataDirectory {

    private final PEFile peFile;
    private final DataDirectoryType type;

    DataDirectory(PEFile peFile, DataDirectoryType type) {
        this.peFile = peFile;
        this.type = type;
    }

    public long getVirtualAddress() throws IOException {
        return peFile.readDWord(peFile.getDataDirectoryOffset(), type.ordinal() * 8);
    }
    
    public long getSize() throws IOException {
        return peFile.readDWord(peFile.getDataDirectoryOffset(), type.ordinal() * 8 + 4);
    }

    public boolean exists() throws IOException {
        return getVirtualAddress() != 0 && getSize() != 0;
    }

    /**
     * Checks if the entry is valid.
     *
     * @throws IOException if the entry is invalid
     * @since 4.2
     */
    void check() throws IOException {
        long address = getVirtualAddress();
        long size = getSize();
        long fileSize = peFile.channel.size();

        if (address >= fileSize) {
            throw new IOException(type.name().replace('_', ' ') + " data directory starts after the end of the file - address=" + address + " (" + String.format("0x%08X", address) + "), size=" + size + ", file size=" + fileSize + " (" + String.format("0x%08X", fileSize) + ")");
        }

        if (address + size > fileSize) {
            throw new IOException(type.name().replace('_', ' ') + " data directory extends beyond the end of the file - address=" + address + " (" + String.format("0x%08X", address) + "), size=" + size + ", file size=" + fileSize + " (" + String.format("0x%08X", fileSize) + ")");
        }
    }

    /**
     * Tells if the data directory is at the end of the file.
     * 
     * @return <code>true</code> if the data directory is at the end of the file, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     * @since 2.0
     */
    public boolean isTrailing() throws IOException {
        return getVirtualAddress() + getSize() == peFile.channel.size();
    }

    public void write(long virtualAddress, int size) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt((int) virtualAddress);
        buffer.putInt(size);
        buffer.flip();
        peFile.write(peFile.getDataDirectoryOffset() + type.ordinal() * 8, buffer);
    }
}
