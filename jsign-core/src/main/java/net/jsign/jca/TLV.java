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

package net.jsign.jca;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.codec.binary.Hex;

/**
 * Simple BER-TLV parser.
 *
 * @since 4.3
 */
class TLV {

    private String tag;
    private byte[] value;
    private List<TLV> children;

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
            return "[TLV tag=" + tag + " value(" + value.length + ")=" + Hex.encodeHexString(value).toUpperCase() + "]";
        } else {
            return "[TLV tag=" + tag + " children=" + children + "]";
        }
    }

    /**
     * Parse a BER-TLV structure
     */
    public static TLV parse(ByteBuffer buffer) {
        List<TLV> map = parseList(buffer);
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
    private static List<TLV> parseList(ByteBuffer buffer) {
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
            if (constructed) {
                tlv.children = parseList(ByteBuffer.wrap(value));
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
}
