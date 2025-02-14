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

package net.jsign.jca;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

/**
 * Simple BER-TLV parser.
 *
 * @since 5.0
 */
class TLV {

    /** Tag in hexadecimal format, or null for the container node of a list */
    private String tag;
    private byte[] value;
    private List<TLV> children;

    private TLV() {
    }

    public TLV(String tag) {
        this.tag = tag;
        children = new ArrayList<>();
    }

    public TLV(String tag, byte[] value) {
        this.tag = tag;
        this.value = value;
    }

    public String tag() {
        return tag;
    }

    public byte[] value() {
        return value;
    }

    public List<TLV> children() {
        return children;
    }

    public TLV find(String... tags) {
        if (tags.length == 0) {
            return this;
        } else if (children != null) {
            List<TLV> values = children;
            String tag = tags[0];
            for (TLV value : values) {
                if (value.tag.equals(tag)) {
                    return value.find(Arrays.copyOfRange(tags, 1, tags.length));
                }
            }
        }

        return null;
    }

    @Override
    public String toString() {
        if (children == null) {
            return "[TLV tag=" + tag + " value(" + value.length + ")=" + Hex.toHexString(value).toUpperCase() + "]";
        } else {
            return "[TLV tag=" + tag + " children=" + children + "]";
        }
    }

    /**
     * Parse a BER-TLV structure
     */
    public static TLV parse(ByteBuffer buffer) {
        return parse(buffer, true);
    }

    /**
     * Parse a BER-TLV structure
     */
    static TLV parse(ByteBuffer buffer, boolean recursive) {
        List<TLV> map = parseList(buffer, recursive);
        if (map.size() == 1) {
            return map.get(0);
        } else {
            // create a root node
            TLV tlv = new TLV();
            tlv.children = map;
            return tlv;
        }
    }

    /**
     * Parse a BER-TLV structure
     */
    private static List<TLV> parseList(ByteBuffer buffer, boolean recursive) {
        List<TLV> list = new ArrayList<>();

        while (buffer.hasRemaining()) {
            // parse the tag
            int tag = buffer.get() & 0xFF;
            boolean constructed = (tag & 0b00100000) != 0;
            if ((tag & 0b00011111) == 0b00011111) {
                tag = (tag << 8) | (buffer.get() & 0xFF);
                while ((tag & 0b10000000) != 0) {
                    tag = (tag << 8) | (buffer.get() & 0xFF);
                }
            }

            // parse the length
            int length = parseLength(buffer);

            // parse the value
            byte[] value;
            if (length >= 0) {
                value = new byte[length];
                buffer.get(value);
            } else {
                buffer.mark();
                int zeroCount = 0;
                while (zeroCount < 2 && buffer.hasRemaining()) {
                    if (buffer.get() == 0) {
                        zeroCount++;
                    } else {
                        zeroCount = 0;
                    }
                }
                long position = buffer.position();
                buffer.reset();
                value = new byte[(int) (position - buffer.position() - 2)];
                buffer.get(value);
            }

            TLV tlv = new TLV();
            tlv.tag = Integer.toHexString(tag).toUpperCase();
            tlv.value = value;
            if (constructed && recursive) {
                tlv.children = parseList(ByteBuffer.wrap(value), recursive);
            }

            list.add(tlv);
        }

        return list;
    }

    /**
     * Parse the length of the value
     */
    private static int parseLength(ByteBuffer buffer) {
        int length = buffer.get() & 0xFF;
        if (length < 0x80) {
            // short form
            return length;
        } else if (length > 0x80) {
            // long form
            int n = length & 0b01111111;
            length = 0;
            for (int i = 0; i < n; i++) {
                length = (length << 8) | (buffer.get() & 0xff);
            }
        } else {
            // indefinite form
            return -1;
        }

        return length;
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
