/*
 * Copyright 2026 Emmanuel Bourg
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

package net.jsign;

import org.junit.Test;
import static org.junit.Assert.*;

public class AnsiFormatterTest {

    @Test
    public void testFormatWithAnsiEnabled() {
        assertEquals("This is \033[31mred\033[0m and \033[1mbold\033[0m.", new AnsiFormatter(true).format("This is <red>red</red> and <b>bold</b>."));
    }

    @Test
    public void testFormatWithAnsiDisabled() {
        assertEquals("This is red and bold.", new AnsiFormatter(false).format("This is <red>red</red> and <b>bold</b>."));
    }

    @Test
    public void testFormatTextWithUnknownTags() {
        String input = "Check the <config.xml> file with <red>caution</red>.";
        assertEquals("Check the <config.xml> file with \033[31mcaution\033[0m.", new AnsiFormatter(true).format(input));
        assertEquals("Check the <config.xml> file with caution.", new AnsiFormatter(false).format(input));
    }

    @Test
    public void testFormatNullText() {
        assertNull(new AnsiFormatter(true).format(null));
        assertNull(new AnsiFormatter(false).format(null));
    }

    @Test
    public void testFormatTextWithoutTags() {
        String plainText = "Hello Jsign";
        assertEquals(plainText, new AnsiFormatter(true).format(plainText));
        assertEquals(plainText, new AnsiFormatter(false).format(plainText));
    }
}
