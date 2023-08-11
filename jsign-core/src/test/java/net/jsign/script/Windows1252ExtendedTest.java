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

package net.jsign.script;

import java.nio.charset.Charset;

import org.junit.Test;

import static java.nio.charset.StandardCharsets.*;
import static org.junit.Assert.*;

public class Windows1252ExtendedTest {

    @Test
    public void testDecodeASCII() {
        byte[] data = "ABC".getBytes(US_ASCII);
        byte[] expected = "ABC".getBytes(UTF_16LE);
        String s = new String(data, Windows1252Extended.INSTANCE);
        assertArrayEquals("Windows-1252 -> UTF-16LE", expected, s.getBytes(UTF_16LE));
    }

    @Test
    public void testEncodeASCII() {
        byte[] expected = "ABC".getBytes(US_ASCII);
        assertArrayEquals(expected, "ABC".getBytes(Windows1252Extended.INSTANCE));
    }

    @Test
    public void testDecodeUndefinedWindows1252Character() {
        byte[] data = { (byte) 0xE1, (byte) 0xBA, (byte) 0x8D}; // ẍ
        byte[] expected = { (byte) 0xE1, (byte) 0x00, (byte) 0xBA, (byte) 0x00, (byte) 0x8D, (byte) 0x00 };
        String s = new String(data, Windows1252Extended.INSTANCE);
        assertArrayEquals("Windows-1252 -> UTF-16LE", expected, s.getBytes(UTF_16LE));
    }

    @Test
    public void testDecodeUndefinedLatin1Character() {
        byte[] data = { (byte) 0xE2, (byte) 0x80, (byte) 0xB0}; // ‰
        byte[] expected = { (byte) 0xE2, (byte) 0x00, (byte) 0xAC, (byte) 0x20, (byte) 0xB0, (byte) 0x00 };
        String s = new String(data, Windows1252Extended.INSTANCE);
        assertArrayEquals("Windows-1252 -> UTF-16LE", expected, s.getBytes(UTF_16LE));
    }

    @Test
    public void testEncodeExtendedCharacter() {
        String s = "€‰ÄËÏÖÜ";

        byte[] expected = s.getBytes(Charset.forName("windows-1252"));
        byte[] actual = s.getBytes(Windows1252Extended.INSTANCE);

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testEncodeUnsupportedCharacter() {
        String s = "ẍ";

        byte[] expected = s.getBytes(Charset.forName("windows-1252"));
        byte[] actual = s.getBytes(Windows1252Extended.INSTANCE);

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testContains() {
        assertFalse("ISO-8859-1", Windows1252Extended.INSTANCE.contains(ISO_8859_1));
        assertTrue("ASCII", Windows1252Extended.INSTANCE.contains(US_ASCII));
        assertTrue("Windows-1252", Windows1252Extended.INSTANCE.contains(Charset.forName("windows-1252")));
        assertTrue("Windows-1252 Extended", Windows1252Extended.INSTANCE.contains(Windows1252Extended.INSTANCE));
    }
}
