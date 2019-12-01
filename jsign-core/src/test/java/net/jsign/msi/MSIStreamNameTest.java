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

import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Test;

import static org.junit.Assert.*;

public class MSIStreamNameTest {

    @Test
    public void testDecode() {
        assertEquals("\u0005DigitalSignature", new MSIStreamName("\u0005DigitalSignature").decode());
        assertEquals("Binary.info", new MSIStreamName("\u430B\u4131\u4735\u433E\u4271\u4832").decode());
        assertEquals("@_Tables", new MSIStreamName("\u4840\u3F7F\u4164\u422F\u4836").decode());
    }

    @Test
    public void testCompare() {
        MSIStreamName name1 = new MSIStreamName("Foo");
        MSIStreamName name2 = new MSIStreamName("Boo");
        MSIStreamName name3 = new MSIStreamName("FooBar");
        
        assertTrue(name1.compareTo(name1) == 0);
        assertTrue(name1.compareTo(name2) > 0);
        assertTrue(name2.compareTo(name1) < 0);
        assertTrue(name3.compareTo(name1) > 0);
        
        Set<MSIStreamName> names = new TreeSet<>();
        names.add(name1);
        names.add(name2);
        names.add(name3);
        
        Iterator<MSIStreamName> iterator = names.iterator();
        assertEquals("1st element", name2, iterator.next());
        assertEquals("2nd element", name1, iterator.next());
        assertEquals("3rd element", name3, iterator.next());
    }

    @Test
    public void testCompareMixedFormat() {
        MSIStreamName name1 = new MSIStreamName("@_X");
        MSIStreamName name2 = new MSIStreamName("\u4840\u3F7F\u4164\u422F\u4836"); // "@_Tables"
        
        assertTrue(name1.compareTo(name2) < 0);
    }

    @Test
    public void testToString() {
        assertEquals("\u0005DigitalSignature", new MSIStreamName("\u0005DigitalSignature").toString());
    }
}
