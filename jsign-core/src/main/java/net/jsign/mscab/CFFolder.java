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

package net.jsign.mscab;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;

/**
 * Cabinet File Folder structure
 *
 * @since 4.0
 */
class CFFolder {

    private final ByteBuffer buffer = ByteBuffer.allocate(BASE_SIZE).order(ByteOrder.LITTLE_ENDIAN);

    /** Base size of the CFFOLDER structure (with no optional per-folder reserved area) */
    public static final int BASE_SIZE = 8;

    /** Offset of the first CFDATA block in this folder */
    public long coffCabStart;   // u4

    /** Number of CFDATA blocks in this folder */
    public int cCFData;         // u2

    /** Compression type indicator */
    public int typeCompress;    // u2

    public static CFFolder read(SeekableByteChannel channel) throws IOException {
        CFFolder folder = new CFFolder();

        int length = channel.read(folder.buffer);
        if (length < BASE_SIZE) {
            throw new IOException("Couldn't read CFFOLDER");
        }
        folder.load();

        return folder;
    }

    private void load() {
        buffer.rewind();
        coffCabStart = buffer.getInt() & 0xFFFFFFFFL;
        cCFData = buffer.getShort() & 0xFFFF;
        typeCompress = buffer.getShort() & 0xFFFF;
        buffer.flip();
    }

    private void save() {
        buffer.rewind();
        buffer.putInt((int) coffCabStart);
        buffer.putShort((short) cCFData);
        buffer.putShort((short) typeCompress);
        buffer.flip();
    }

    public void write(SeekableByteChannel channel) throws IOException {
        save();
        channel.write(buffer);
    }

    public void digest(MessageDigest digest) {
        save();
        digest.update(buffer.array());
    }
}
