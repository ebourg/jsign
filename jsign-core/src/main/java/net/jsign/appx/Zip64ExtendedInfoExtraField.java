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
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static java.nio.ByteOrder.*;

/**
 * ZIP64 Extended Information Extra Field (0x0001):
 *
 * <pre>
 * Tag for this extra block type                 2 bytes  (0x0001: ZIP64)
 * Size of this extra block                      2 bytes
 * Original uncompressed file size               8 bytes  (optional)
 * Size of compressed data                       8 bytes  (optional)
 * Offset of local header record                 8 bytes  (optional)
 * Number of the disk on which this file starts  4 bytes  (optional)
 * </pre>
 *
 * @since 6.0
 */
class Zip64ExtendedInfoExtraField extends ExtraField {

    public long uncompressedSize;
    public long compressedSize;
    public long localHeaderOffset;
    public int diskNumberStart;

    public Zip64ExtendedInfoExtraField(boolean uncompressedSize, boolean compressedSize, boolean localHeaderOffset, boolean diskNumberStart) {
        this.id = 1;
        this.uncompressedSize = uncompressedSize ? 0 : -1;
        this.compressedSize = compressedSize ? 0 : -1;
        this.localHeaderOffset = localHeaderOffset ? 0 : -1;
        this.diskNumberStart = diskNumberStart ? 0 : -1;
    }

    public Zip64ExtendedInfoExtraField(long uncompressedSize, long compressedSize, long localHeaderOffset, int diskNumberStart) {
        this.id = 1;
        this.uncompressedSize = uncompressedSize;
        this.compressedSize = compressedSize;
        this.localHeaderOffset = localHeaderOffset;
        this.diskNumberStart = diskNumberStart;
        update();
    }

    @Override
    protected void parse() throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(data).order(LITTLE_ENDIAN);
        try {
            if (uncompressedSize != -1) {
                uncompressedSize = buffer.getLong();
            }
            if (compressedSize != -1) {
                compressedSize = buffer.getLong();
            }
            if (localHeaderOffset != -1) {
                localHeaderOffset = buffer.getLong();
            }
            if (diskNumberStart != -1) {
                diskNumberStart = buffer.getInt();
            }
        } catch (BufferUnderflowException e) {
            throw new IOException("Invalid ZIP64 extended information extra field", e);
        }
    }

    @Override
    public void update() {
        int size = 0;
        if (uncompressedSize != -1) {
            size += 8;
        }
        if (compressedSize != -1) {
            size += 8;
        }
        if (localHeaderOffset != -1) {
            size += 8;
        }
        if (diskNumberStart != -1) {
            size += 4;
        }

        data = new byte[size];
        ByteBuffer buffer = ByteBuffer.wrap(data).order(LITTLE_ENDIAN);
        if (uncompressedSize != -1) {
            buffer.putLong(uncompressedSize);
        }
        if (compressedSize != -1) {
            buffer.putLong(compressedSize);
        }
        if (localHeaderOffset != -1) {
            buffer.putLong(localHeaderOffset);
        }
        if (diskNumberStart != -1) {
            buffer.putInt(diskNumberStart);
        }
    }
}
