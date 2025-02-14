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

package net.jsign.zip;

import java.nio.ByteBuffer;

import org.junit.Test;

import static java.nio.ByteOrder.*;
import static org.junit.Assert.*;

public class ExtraFieldTest {

    @Test
    public void testReadWriteEmptyField() throws Exception {
        byte[] data = new byte[] { 0x02, 0x00, 0x00, 0x00 };
        ExtraField field = new ExtraField();
        field.read(ByteBuffer.wrap(data).order(LITTLE_ENDIAN));
        assertEquals("id", 2, field.id);
        assertEquals("data length", 0, field.data.length);
        assertEquals("size", 4, field.size());

        ByteBuffer buffer = ByteBuffer.allocate(field.size()).order(LITTLE_ENDIAN);
        field.write(buffer);
        assertArrayEquals("data", data, buffer.array());
    }

    @Test
    public void testReadWriteZip64ExtraField() throws Exception {
        byte[] data = new byte[] { 0x01, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        ExtraField field = new Zip64ExtendedInfoExtraField(false, false, true, false);
        field.read(ByteBuffer.wrap(data).order(LITTLE_ENDIAN));
        assertEquals("id", 1, field.id);
        assertEquals("data length", 8, field.data.length);
        assertEquals("size", 12, field.size());

        ByteBuffer buffer = ByteBuffer.allocate(field.size()).order(LITTLE_ENDIAN);
        field.write(buffer);
        assertArrayEquals("data", data, buffer.array());
    }
}
