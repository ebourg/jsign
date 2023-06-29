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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyStore;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.KeyStoreBuilder;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.SignatureAssert.*;
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
        try (PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"))) {
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
        try (PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"))) {
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
    }

    @Test
    public void testPrintInfo() throws Exception {
        ByteArrayOutputStream out;
        try (PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"))) {
            out = new ByteArrayOutputStream();
            file.printInfo(out);
        }

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
        try (PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"))) {
            assertEquals("checksum", 0x0000E7F5, file.computeChecksum());
        }
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
        try (PEFile file = new PEFile(new File("target/test-classes/wineyes.exe"))) {
            String sha1 = Hex.toHexString(file.computeDigest(SHA1));
            String sha256 = Hex.toHexString(file.computeDigest(SHA256.getMessageDigest()));

            assertEquals("d27ec498912807ddfc4bec2be4f62c42814836f3", sha1);
            assertEquals("7bb369df020cea757619e1c1d678dbca06b638f2cc45b740b5eacfc21e76b160", sha256);
        }
    }

    @Test
    public void testComputeDigestNotPadded() throws Exception {
        File testFile = new File("target/test-classes/wineyes.exe");

        assertEquals("Test file not padded", 0, testFile.length() % 8);

        File testFilePadded = new File("target/test-classes/wineyes-padded.exe");
        File testFileNotPadded = new File("target/test-classes/wineyes-notpadded.exe");
        FileUtils.copyFile(testFile, testFilePadded);
        FileUtils.copyFile(testFile, testFileNotPadded);

        try (PEFile file1 = new PEFile(testFilePadded);
             PEFile file2 = new PEFile(testFileNotPadded)) {
            file1.write(file1.channel.size(), new byte[8]);
            file2.write(file2.channel.size(), new byte[3]);

            String digestPadded = Hex.toHexString(file1.computeDigest(SHA1));
            String digestNotPadded = Hex.toHexString(file2.computeDigest(SHA1));

            assertEquals(digestPadded, digestNotPadded);
        }
    }

    @Test(expected = IOException.class)
    public void testComputeDigestInvalidCertificateTableNegativeAddress() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-fuzzed.exe");
        FileUtils.copyFile(srcFile, destFile);

        try (PEFile file = new PEFile(destFile)) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            certificateTable.write(Integer.MIN_VALUE, 1024);
            file.computeDigest(SHA1);
        }
    }

    @Test(expected = IOException.class)
    public void testComputeDigestInvalidCertificateTableNegativeSize() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-fuzzed.exe");
        FileUtils.copyFile(srcFile, destFile);

        try (PEFile file = new PEFile(destFile)) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            certificateTable.write(1024, Integer.MIN_VALUE);
            file.computeDigest(SHA1);
        }
    }

    @Test(expected = IOException.class)
    public void testComputeDigestInvalidCertificateTableAfterEndOfFile() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-fuzzed.exe");
        FileUtils.copyFile(srcFile, destFile);

        try (PEFile file = new PEFile(destFile)) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            certificateTable.write(Integer.MAX_VALUE, Integer.MAX_VALUE);
            file.computeDigest(SHA1);
        }
    }

    @Test
    public void testCertificateTableAfterEndOfFile() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-fuzzed.exe");
        FileUtils.copyFile(srcFile, destFile);

        try (PEFile file = new PEFile(destFile)) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            certificateTable.write(Integer.MAX_VALUE, 1024);

            assertTrue("Certificate table after the end of the file not ignored", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testCertificateTableInvalidSize() throws Exception {
        File srcFile = new File("target/test-classes/wineyes.exe");
        File destFile = new File("target/test-classes/wineyes-fuzzed.exe");
        FileUtils.copyFile(srcFile, destFile);

        try (PEFile file = new PEFile(destFile)) {
            DataDirectory certificateTable = file.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            certificateTable.write(file.channel.size() - 512, Integer.MAX_VALUE);
            file.channel.position(certificateTable.getVirtualAddress());
            file.channel.write((ByteBuffer) ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(Integer.MAX_VALUE).flip());

            assertTrue("Certificate table with invalid size not ignored", file.getSignatures().isEmpty());
        }
    }

    @Test
    public void testRemoveSignature() throws Exception {
        File sourceFile = new File("target/test-classes/wineyes.exe");
        File targetFile = new File("target/test-classes/wineyes-unsigned.exe");

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);

        try (PEFile file = new PEFile(targetFile)) {
            file.setSignature(null);
            signer.sign(file);
            assertSigned(file, SHA256);
            file.setSignature(null);
            assertNotSigned(file);
        }
    }
}
