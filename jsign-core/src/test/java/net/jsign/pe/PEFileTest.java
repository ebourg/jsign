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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static net.jsign.DigestAlgorithm.*;
import static org.junit.Assert.*;

public class PEFileTest {

    @Test
    public void testIsMSCabinetFile() throws Exception {
        assertTrue(PEFile.isPEFile(new File("target/test-classes/wineyes.exe")));
        assertFalse(PEFile.isPEFile(new File("target/test-classes/mscab/sample1.cab")));
        assertFalse(PEFile.isPEFile(new File("target")));
        assertFalse(PEFile.isPEFile(new File("target/non-existent")));
    }

    @Test
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
        assertEquals(0, file.getWin32VersionValue());
        assertEquals(49152, file.getSizeOfImage());
        assertEquals(4096, file.getSizeOfHeaders());
        assertEquals(Subsystem.WINDOWS_GUI, file.getSubsystem());
        assertEquals(0, file.getLoaderFlags());
        assertEquals(16, file.getNumberOfRvaAndSizes());
    }

    @Test
    public void testLoadNonExecutable() {
        try {
            new PEFile(new File("pom.xml"));
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("Exception message", "DOS header signature not found", e.getMessage());
        }
    }

    /**
     * Attempts to open a DOS executable that isn't a Portable Executable
     */
    @Test
    public void testDosExecutable() throws Exception {
        try {
            new PEFile(new File("target/test-classes/MORE.EXE")); // MORE.EXE comes from FreeDOS and is GPL licensed
            fail("No exception thrown");
        } catch (IOException e) {
            if (!e.getMessage().contains("PE signature not found as expected")) {
                throw e;
            }
        }
    }

    @Test
    public void testGetSections() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        
        List<Section> sections = file.getSections();
        assertNotNull(sections);
        assertFalse("No section found", sections.isEmpty());
        for (Section section : file.getSections()) {
            assertNotNull("null section found", section);
            assertEquals(0, section.getPointerToRelocations());
            assertEquals(0, section.getPointerToLineNumbers());
            assertEquals(0, section.getNumberOfRelocations());
            assertEquals(0, section.getNumberOfLineNumbers());
        }
    }

    @Test
    public void testPrintInfo() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        file.printInfo(out);
        
        assertNotNull(out.toString());
        assertFalse(out.toString().isEmpty());

        System.out.println(out);
    }

    @Test
    public void testPadNoOp() throws Exception {
        File testFile = new File("target/test-classes/wineyes.exe");
        File testFilePadded = new File("target/test-classes/wineyes-padded.exe");
        FileUtils.copyFile(testFile, testFilePadded);
        
        PEFile file = new PEFile(testFilePadded);
        file.pad(8);
        file.close();
        
        assertEquals("Padded file size", testFile.length(), testFilePadded.length());
    }

    @Test
    public void testPad() throws Exception {
        File testFile = new File("target/test-classes/wineyes.exe");
        File testFilePadded = new File("target/test-classes/wineyes-padded.exe");
        FileUtils.copyFile(testFile, testFilePadded);

        PEFile file = new PEFile(testFilePadded);
        file.pad(7);
        file.close();

        assertEquals("Padded file size", testFile.length() + 4, testFilePadded.length());
    }

    @Test
    public void testComputeChecksum() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        
        assertEquals("checksum", 0x0000E7F5, file.computeChecksum());
    }

    @Test
    public void testUpdateChecksum() throws Exception {
        // Expand the test file beyond the size of the buffer used in updateChecksum() (> 64K)
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-big.exe");
        FileUtils.copyFile(srcFile, destFile);
        RandomAccessFile raf = new RandomAccessFile(destFile, "rw");
        raf.setLength(1024 * 1024 + 73);
        raf.close();

        PEFile file = new PEFile(destFile);
        file.updateChecksum();
        assertEquals("checksum", 0x0010483E, file.getCheckSum());
    }

    @Test
    public void testComputeDigest() throws Exception {
        PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"));
        
        String sha1 = Hex.toHexString(file.computeDigest(SHA1));
        String sha256 = Hex.toHexString(file.computeDigest(SHA256));
        
        assertEquals("d27ec498912807ddfc4bec2be4f62c42814836f3", sha1);
        assertEquals("7bb369df020cea757619e1c1d678dbca06b638f2cc45b740b5eacfc21e76b160", sha256);
    }
}
