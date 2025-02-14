/*
 * Copyright 2024 Emmanuel Bourg
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
import java.security.MessageDigest;

/**
 * Structure of the per-cabinet reserve.
 *
 * <pre>
 * length of the structure 1           2 bytes
 * length of the structure 2           2 bytes
 * structure 1                         (variable size)
 * structure 2 (signature)             (variable size) (CABSignature or PKCS#7 signed data)
 * </pre>
 *
 * @since 7.0
 */
class CFReserve {

    public byte[] structure1 = new byte[0];
    public byte[] structure2 = new byte[0];
    public int minSize = -1;

    public CFReserve() {
    }

    public CFReserve(CFReserve reserve) {
        this.structure1 = reserve.structure1.clone();
        this.structure2 = reserve.structure2.clone();
    }

    public void read(byte[] abReserve) throws IOException {
        if (abReserve.length < 4) {
            throw new IOException("Invalid size of the header reserve");
        }
        ByteBuffer buffer = ByteBuffer.wrap(abReserve).order(ByteOrder.LITTLE_ENDIAN);
        int length1 = buffer.getShort() & 0xFFFF;
        int length2 = buffer.getShort() & 0xFFFF;
        if (4 + length1 + length2 > abReserve.length) {
            throw new IOException("Invalid data in the header reserve");
        }

        structure1 = new byte[length1];
        buffer.get(structure1);
        structure2 = new byte[length2];
        buffer.get(structure2);
    }

    public int size() {
        return Math.max(minSize, 4 + structure1.length + structure2.length);
    }

    /**
     * Tells if both structures are empty.
     */
    public boolean isEmpty() {
        return structure1.length == 0 && structure2.length == 0;
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(size()).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) structure1.length);
        buffer.putShort((short) structure2.length);
        buffer.put(structure1);
        buffer.put(structure2);
        buffer.position(buffer.capacity());
        buffer.flip();

        return buffer;
    }

    public void digest(MessageDigest digest) {
        // digest only the first structure since the second one is used for the signature
        ByteBuffer buffer = ByteBuffer.allocate(2 + structure1.length).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) structure1.length);
        buffer.put(structure1);
        buffer.flip();
        digest.update(buffer);
    }
}
