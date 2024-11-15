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

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.*;

public class TLVTest {

    @Test
    public void testParseList() {
        byte[] data = Hex.decode("01 01 86 02 02 05 05 08 04 01 26 9A 33".replaceAll(" ", ""));
        TLV tlv = TLV.parse(ByteBuffer.wrap(data));

        assertNull("Root tag", tlv.tag());
        assertEquals("Length", 3, tlv.children().size());
        assertEquals("Tag 1", "1", tlv.children().get(0).tag());
        assertEquals("Tag 2", "2", tlv.children().get(1).tag());
        assertEquals("Tag 3", "8", tlv.children().get(2).tag());
        assertEquals("Value 1", "86", Hex.toHexString(tlv.children().get(0).value()));
        assertEquals("Value 2", "0505", Hex.toHexString(tlv.children().get(1).value()));
        assertEquals("Value 3", "01269a33", Hex.toHexString(tlv.children().get(2).value()));
    }

    @Test
    public void testWriteLength() {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        TLV.writeLength(buffer, 0x64);
        assertEquals(0x64, buffer.get(0) & 0xFF);
        assertEquals(0x00, buffer.get(1) & 0xFF);

        buffer = ByteBuffer.allocate(4);
        TLV.writeLength(buffer, 0x80);
        assertEquals(0x81, buffer.get(0) & 0xFF);
        assertEquals(0x80, buffer.get(1) & 0xFF);
        assertEquals(0x00, buffer.get(2) & 0xFF);

        buffer = ByteBuffer.allocate(4);
        TLV.writeLength(buffer, 0x100);
        assertEquals(0x82, buffer.get(0) & 0xFF);
        assertEquals(0x01, buffer.get(1) & 0xFF);
        assertEquals(0x00, buffer.get(2) & 0xFF);
        assertEquals(0x00, buffer.get(3) & 0xFF);

        buffer = ByteBuffer.allocate(4);
        TLV.writeLength(buffer, 0x12345);
        assertEquals(0x83, buffer.get(0) & 0xFF);
        assertEquals(0x01, buffer.get(1) & 0xFF);
        assertEquals(0x23, buffer.get(2) & 0xFF);
        assertEquals(0x45, buffer.get(3) & 0xFF);
    }

    @Test
    public void testEncode() {
        byte[] data = Hex.decode("01 01 86 02 02 05 05 08 04 01 26 9A 33".replaceAll(" ", ""));
        TLV tlv = TLV.parse(ByteBuffer.wrap(data));

        assertArrayEquals("Encoded", data, tlv.getEncoded());
    }
}
