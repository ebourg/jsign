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
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Extra field of a ZIP entry.
 *
 * @since 5.1
 */
class ExtraField {

    public int id;
    public byte[] data = new byte[0];

    public void read(ByteBuffer buffer) throws IOException {
        id = buffer.getShort() & 0xFFFF;
        int size = buffer.getShort() & 0xFFFF;
        if (size > 0) {
            data = new byte[size];
            buffer.get(data);
        }

        parse();
    }

    public void write(ByteBuffer buffer) {
        update();

        buffer.putShort((short) id);
        buffer.putShort((short) data.length);
        buffer.put(data);
    }

    /**
     * Load the field from the data buffer.
     */
    protected void parse() throws IOException {
    }

    /**
     * Update the data buffer from the field.
     */
    protected void update() {
    }

    public int size() {
        return 4 + data.length;
    }

    public static Map<Integer, ExtraField> parseAll(ByteBuffer buffer, boolean uncompressedSize, boolean compressedSize, boolean localHeaderOffset, boolean diskNumberStart) throws IOException {
        Map<Integer, ExtraField> fields = new LinkedHashMap<>();
        while (buffer.remaining() >= 4) {
            ExtraField field = new ExtraField();
            field.read(buffer);
            if (field.id == 1) {
                Zip64ExtendedInfoExtraField zip64 = new Zip64ExtendedInfoExtraField(uncompressedSize, compressedSize, localHeaderOffset, diskNumberStart);
                zip64.id = field.id;
                zip64.data = field.data;
                zip64.parse();
                fields.put(field.id, zip64);
            } else {
                fields.put(field.id, field);
            }
        }
        return fields;
    }
}
