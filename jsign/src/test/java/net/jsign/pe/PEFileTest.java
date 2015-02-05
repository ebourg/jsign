/**
 * Copyright 2012 Emmanuel Bourg
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
import java.io.PrintWriter;
import java.io.StringWriter;

import junit.framework.TestCase;

/**
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PEFileTest extends TestCase {

    public void testLoad() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        
        assertEquals(MachineType.I386, file.getMachineType());
        assertEquals(4, file.getNumberOfSections());
        assertEquals(0, file.getPointerToSymbolTable());
        assertEquals(0, file.getNumberOfSymbols());
        assertEquals(224, file.getSizeOfOptionalHeader());
        assertEquals(PEFormat.PE32, file.getFormat());
        assertEquals(24576, file.getSizeOfCode());
        assertEquals(20480, file.getSizeOfInitializedData());
        assertEquals(0, file.getSizeOfUninitializedData());
        assertEquals(0x400000, file.getImageBase());
        assertEquals(4096, file.getSectionAlignment());
        assertEquals(4096, file.getFileAlignment());
        assertEquals(4, file.getMajorOperatingSystemVersion());
        assertEquals(0, file.getMinorOperatingSystemVersion());
        assertEquals(4, file.getMajorSubsystemVersion());
        assertEquals(0, file.getMinorSubsystemVersion());
        assertEquals(49152, file.getSizeOfImage());
        assertEquals(4096, file.getSizeOfHeaders());
        assertEquals(Subsystem.WINDOWS_GUI, file.getSubsystem());
        assertEquals(16, file.getNumberOfRvaAndSizes());
    }

    public void testPrintInfo() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        StringWriter out = new StringWriter();
        file.printInfo(new PrintWriter(out));

        assertNotNull(out.toString());
        assertFalse(out.toString().isEmpty());

        System.out.println(out);
    }

    public void testComputeChecksum() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        
        assertEquals(file.computeChecksum(), 0x0000E7F5);
    }
}
