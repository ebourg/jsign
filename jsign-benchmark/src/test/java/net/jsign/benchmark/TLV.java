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

package net.jsign.benchmark;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple BER-TLV writer.
 */
class TLV {

    /** Tag in hexadecimal format, or null for the container node of a list */
    private String tag;
    private byte[] value;
    private List<TLV> children;

    public TLV(String tag) {
        this.tag = tag;
        children = new ArrayList<>();
    }

    public TLV(String tag, byte[] value) {
        this.tag = tag;
        this.value = value;
    }

    public byte[] value() {
        return value;
    }

    public List<TLV> children() {
        return children;
    }

    /**
     * Returns the number of bytes required to encode the specified length
     */
    private static int sizeOfLengthField(int length) {
        return length < 0x80 ? 1 : 1 + numberOfBytes(length);
    }

    private static int numberOfBytes(int value) {
        return (int) (Math.log(value) / Math.log(256)) + 1;
    }

    int getValueLength() {
        if (children == null) {
            return value.length;
        } else {
            int length = 0;
            for (TLV child : children) {
                length += child.getEncodedLength();
            }
            return length;
        }
    }

    /**
     * Returns the number of bytes required to encode this TLV
     */
    int getEncodedLength() {
        int length = getValueLength();
        return 1 + sizeOfLengthField(length) + length;
    }

    void write(ByteBuffer buffer) {
        if (tag != null) {
            buffer.put((byte) Integer.parseInt(tag, 16));
            writeLength(buffer, getValueLength());
        }

        if (children == null) {
            buffer.put(value);
        } else {
            for (TLV child : children) {
                child.write(buffer);
            }
        }
    }

    static void writeLength(ByteBuffer buffer, int length) {
        if (length < 0x80) {
            // short form
            buffer.put((byte) length);
        } else {
            // long form
            int n = numberOfBytes(length);
            buffer.put((byte) (0x80 | n));
            for (int i = 0; i < n; i++) {
                int b = 0xFF & (length >> (8 * (n - i - 1)));
                buffer.put((byte) b);
            }
        }
    }

    /**
     * Returns the encoded representation of this TLV
     */
    public byte[] getEncoded() {
        ByteBuffer buffer = ByteBuffer.allocate(tag == null ? getValueLength() : getEncodedLength());
        write(buffer);
        return buffer.array();
    }
}
