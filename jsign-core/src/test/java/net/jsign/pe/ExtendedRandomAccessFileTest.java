/**
 * Copyright 2016 Emmanuel Bourg
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

package net.jsign.pe;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import junit.framework.TestCase;

public class ExtendedRandomAccessFileTest extends TestCase {
    
    public void testReadWord() throws Exception {
        File file = new File("target/test-classes/data1.bin");
        FileOutputStream out = new FileOutputStream(file);
        out.write(0x01);
        out.write(0x02);
        out.close();
        
        ExtendedRandomAccessFile raf = new ExtendedRandomAccessFile(file, "rw");
        
        assertEquals(0x0201, raf.readWord());

        try {
            raf.readWord();
            fail("No exception thrown at the end of the file");
        } catch (IOException e) {
            // expected
        }
    }

    public void testReadDWord() throws Exception {
        File file = new File("target/test-classes/data2.bin");
        FileOutputStream out = new FileOutputStream(file);
        out.write(0x01);
        out.write(0x02);
        out.write(0x03);
        out.write(0x04);
        out.close();
        
        ExtendedRandomAccessFile raf = new ExtendedRandomAccessFile(file, "rw");
        
        assertEquals(0x04030201, raf.readDWord());

        try {
            raf.readDWord();
            fail("No exception thrown at the end of the file");
        } catch (IOException e) {
            // expected
        }
    }

    public void testReadQWord() throws Exception {
        File file = new File("target/test-classes/data3.bin");
        FileOutputStream out = new FileOutputStream(file);
        out.write(0x01);
        out.write(0x02);
        out.write(0x03);
        out.write(0x04);
        out.write(0x05);
        out.write(0x06);
        out.write(0x07);
        out.write(0x08);
        out.close();
        
        ExtendedRandomAccessFile raf = new ExtendedRandomAccessFile(file, "rw");
        
        assertEquals(0x0807060504030201L, raf.readQWord());

        try {
            raf.readQWord();
            fail("No exception thrown at the end of the file");
        } catch (IOException e) {
            // expected
        }
    }
}
