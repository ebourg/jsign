/**
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
public class DataDirectory {

    private final PEFile peFile;
    private final int index;

    DataDirectory(PEFile peFile, int index) {
        this.peFile = peFile;
        this.index = index;
    }

    public long getVirtualAddress() {
        return peFile.readDWord(peFile.getDataDirectoryOffset(), index * 8);
    }
    
    public int getSize() {
        return (int) peFile.readDWord(peFile.getDataDirectoryOffset(), index * 8 + 4);
    }

    public boolean exists() {
        return getVirtualAddress() != 0 && getSize() != 0;
    }

    /**
     * Fill the data directory with zeros.
     * 
     * @since 2.0
     */
    public void erase() {
        peFile.write(getVirtualAddress(), new byte[getSize()]);
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

    public void write(long virtualAddress, int size) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt((int) virtualAddress);
        buffer.putInt(size);
        peFile.write(peFile.getDataDirectoryOffset() + index * 8, buffer.array());
    }
}
