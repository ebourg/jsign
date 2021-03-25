/**
 * Copyright 2019 Emmanuel Bourg
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

package net.jsign.msi;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Decodes and orders file names in MSI packages.
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
class MSIStreamName implements Comparable<MSIStreamName> {

    /** The base 64 alphabet used to encode the characters */
    private static final char[] ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._".toCharArray();

    /** Bit mask used to extract the lower 6 bits*/
    private static final byte MASK = 0x3f;

    /** The encoded name */
    private final String name;

    /** The encoded name in UTF-16 */
    private final byte[] nameUTF16;

    /**
     * Creates a MSI stream name
     *
     * @param name the encoded stream name
     */
    public MSIStreamName(String name) {
        this.name = name;
        this.nameUTF16 = name.getBytes(StandardCharsets.UTF_16LE);
    }

    /**
     * Returns the decoded name of the stream.
     */
    public String decode() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for (char c : name.toCharArray()) {
            if (c >= 0x3800 && c < 0x4840) {
                if (c < 0x4800) {
                    // 0x3800-0x383F
                    c -= 0x3800;
                    out.write(ALPHABET[(c & MASK)]);
                    out.write(ALPHABET[((c >> 6) & MASK)]);
                } else {
                    // 0x4800-0x483F
                    out.write(ALPHABET[c - 0x4800]);
                }
            } else {
                // other characters are passed through
                out.write(c);
            }
        }

        return new String(out.toByteArray(), Charset.forName("UTF-8"));
    }

    public String toString() {
        return decode();
    }

    public int compareTo(MSIStreamName other) {
        byte[] a = this.nameUTF16;
        byte[] b = other.nameUTF16;

        int size = Math.min(a.length, b.length);
        for (int i = 0; i < size; i++) {
            if (a[i] != b[i]) {
                return (a[i] & 0xFF) - (b[i] & 0xFF);
            }
        }
        
        return a.length - b.length;
    }
}
