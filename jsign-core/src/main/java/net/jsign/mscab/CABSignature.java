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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * CABSignature structure found in the per-cabinet reserved area.
 *
 * <pre>
 * header                              4 bytes  (0x00100000)
 * position of the signature           4 bytes
 * size of the signature               4 bytes
 * unused                              8 bytes
 * </pre>
 *
 * @since 4.0
 */
class CABSignature {

    /** Size of the CABSignature structure */
    public static final int SIZE = 20;

    /** Header of the signature in the per-cabinet reserved area (two zero bytes + size of the signature) */
    public static final int HEADER = 0x00100000;

    /** Actual header of the structure */
    public int header = HEADER;

    /** Position of the signature in the file (u4) */
    public long offset;

    /** Size of the signature (u4) */
    public long length;

    /** Unused extra data (u8) */
    private long filler;

    public CABSignature() {
    }

    public CABSignature(byte[] array) {
        ByteBuffer buffer = ByteBuffer.wrap(array).order(ByteOrder.LITTLE_ENDIAN);
        buffer.rewind();
        header = buffer.getInt();
        offset = buffer.getInt() & 0xFFFFFFFFL;
        length = buffer.getInt() & 0xFFFFFFFFL;
        filler = buffer.getLong();
        buffer.flip();
    }

    public byte[] array() {
        ByteBuffer buffer = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(header);
        buffer.putInt((int) offset);
        buffer.putInt((int) length);
        buffer.putLong(filler);
        buffer.flip();

        return buffer.array();
    }
}
