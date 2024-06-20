/**
 * Copyright 2021 Emmanuel Bourg and contributors
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

package net.jsign.mscab;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import net.jsign.AuthenticodeSigner;
import net.jsign.KeyStoreBuilder;

import static net.jsign.DigestAlgorithm.*;
import static net.jsign.SignatureAssert.*;
import static org.junit.Assert.*;

public class MSCabinetFileTest {

    @Test
    public void testIsMSCabinetFile() throws Exception {
        assertTrue(MSCabinetFile.isMSCabinetFile(new File("target/test-classes/mscab/sample1.cab")));
        assertFalse(MSCabinetFile.isMSCabinetFile(new File("target/test-classes/wineyes.exe")));
        assertFalse(MSCabinetFile.isMSCabinetFile(new File("target")));
        assertFalse(MSCabinetFile.isMSCabinetFile(new File("target/non-existent")));
    }

    @Test
    public void testCabinetTooShort() {
        byte[] data = new byte[CFHeader.BASE_SIZE];

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "MSCabinet file too short", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithInvalidReserveHeader() {
        CFReserve reserve = new CFReserve();
        reserve.structure2 = new byte[CABSignature.SIZE];

        CFHeader header = new CFHeader();
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.setReserve(reserve);

        byte[] data = new byte[128];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));
        data[0x28] = 'C';
        data[0x29] = 'A';
        data[0x2A] = 'F';
        data[0x2B] = 'E';

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "Invalid data in the header reserve", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithMisplacedSignature() {
        CFHeader header = new CFHeader();
        header.cbCabinet = 4096;
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE + 4;

        CABSignature signature = new CABSignature();
        signature.offset = (int) header.cbCabinet - 512;
        signature.length = 1024;

        CFReserve reserve = new CFReserve();
        reserve.structure2 = signature.array();

        header.reserve = reserve;

        byte[] data = new byte[(int) header.cbCabinet];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "MSCabinet file is corrupt: signature data (offset=3584, size=1024) after the end of the file", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithSignatureAfterEOF() {
        CFHeader header = new CFHeader();
        header.cbCabinet = 4096;
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE + 4;

        CABSignature signature = new CABSignature();
        signature.offset = header.cbCabinet * 2;
        signature.length = 1024;

        CFReserve reserve = new CFReserve();
        reserve.structure2 = signature.array();

        header.reserve = reserve;

        byte[] data = new byte[512];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "MSCabinet file is corrupt: signature data (offset=8192, size=1024) after the end of the file", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithBadSignatureOffset() {
        CFHeader header = new CFHeader();
        header.cbCabinet = 4096;
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE + 4;

        CABSignature signature = new CABSignature();
        signature.offset = (int) header.cbCabinet - 123;
        signature.length = 1024;

        CFReserve reserve = new CFReserve();
        reserve.structure2 = signature.array();

        header.reserve = reserve;

        byte[] data = new byte[(int) (header.cbCabinet + signature.length)];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "MSCabinet file is corrupt: the declared size of the file (4096) doesn't match the offset of the signature (3973)", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithBadSignatureLength() {
        CFHeader header = new CFHeader();
        header.cbCabinet = 4096;
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE + 4;

        CABSignature signature = new CABSignature();
        signature.offset = (int) header.cbCabinet;
        signature.length = 1024;

        CFReserve reserve = new CFReserve();
        reserve.structure2 = signature.array();

        header.reserve = reserve;

        byte[] data = new byte[(int) (header.cbCabinet + signature.length) + 123];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("Exception not thrown");
        } catch (IOException e) {
            assertEquals("message", "MSCabinet file is corrupt: the declared size of the file (4096) and the size of the signature (1024) are inconsistent with the actual size of the file (5243)", e.getMessage());
        }
    }

    @Test
    public void testRemoveSignature() throws Exception {
        File sourceFile = new File("target/test-classes/mscab/sample1.cab");
        File targetFile = new File("target/test-classes/mscab/sample1-unsigned.cab");

        FileUtils.copyFile(sourceFile, targetFile);

        KeyStore keystore = new KeyStoreBuilder().keystore("target/test-classes/keystores/keystore.jks").storepass("password").build();
        AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);

        try (MSCabinetFile file = new MSCabinetFile(targetFile)) {
            file.setSignature(null);
            signer.sign(file);
            assertSigned(file, SHA256);
            file.setSignature(null);
            assertNotSigned(file);
            assertEquals("file size", sourceFile.length() + 24, targetFile.length());
        }
    }

    @Test
    public void testHasSignature() throws Exception {
        try (SeekableByteChannel channel = Files.newByteChannel(new File("target/test-classes/mscab/sample1.cab").toPath(), StandardOpenOption.READ)) {
            CFHeader header = new CFHeader();
            header.read(channel);
            assertFalse(header.hasSignature());
        }
        try (SeekableByteChannel channel = Files.newByteChannel(new File("target/test-classes/mscab/sample4.cab").toPath(), StandardOpenOption.READ)) {
            CFHeader header = new CFHeader();
            header.read(channel);
            assertFalse(header.hasSignature());
        }
    }
}
