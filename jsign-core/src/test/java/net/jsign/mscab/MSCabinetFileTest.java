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

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.Test;

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
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("MSCabinet file too short", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithInvalidReservedField() {
        CFHeader header = new CFHeader();
        System.arraycopy("MSCF".getBytes(), 0, header.signature, 0, 4);
        header.csumHeader = 1;

        byte[] data = new byte[512];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("MSCabinet file is corrupt: invalid reserved field in the header", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithInvalidSignatureSize() {
        CFHeader header = new CFHeader();
        System.arraycopy("MSCF".getBytes(), 0, header.signature, 0, 4);
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = 64;
        header.abReserved = new byte[64];

        byte[] data = new byte[128];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("MSCabinet file is corrupt: cabinet reserved area size is 64 instead of 20", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithInvalidSignatureHeader() {
        CFHeader header = new CFHeader();
        System.arraycopy("MSCF".getBytes(), 0, header.signature, 0, 4);
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE;
        header.abReserved = new byte[CABSignature.SIZE];
        header.abReserved[0] = 'C';
        header.abReserved[1] = 'A';
        header.abReserved[2] = 'F';
        header.abReserved[3] = 'E';

        byte[] data = new byte[128];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("MSCabinet file is corrupt: signature header is 1162232131", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithMisplacedSignature() {
        CFHeader header = new CFHeader();
        System.arraycopy("MSCF".getBytes(), 0, header.signature, 0, 4);
        header.cbCabinet = 4096;
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE;
        header.abReserved = new byte[CABSignature.SIZE];
        CABSignature signature = header.getSignature();
        signature.header = CABSignature.HEADER;
        signature.offset = (int) header.cbCabinet - 512;
        signature.length = 1024;
        header.abReserved = signature.array();

        byte[] data = new byte[(int) header.cbCabinet];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("MSCabinet file is corrupt: signature data (offset=3584, size=1024) after the end of the file", e.getMessage());
        }
    }

    @Test
    public void testCabinetWithSignatureAfterEOF() {
        CFHeader header = new CFHeader();
        System.arraycopy("MSCF".getBytes(), 0, header.signature, 0, 4);
        header.cbCabinet = 4096;
        header.flags |= CFHeader.FLAG_RESERVE_PRESENT;
        header.cbCFHeader = CABSignature.SIZE;
        header.abReserved = new byte[CABSignature.SIZE];
        CABSignature signature = header.getSignature();
        signature.header = CABSignature.HEADER;
        signature.offset = header.cbCabinet * 2;
        signature.length = 1024;
        header.abReserved = signature.array();

        byte[] data = new byte[512];
        header.write(ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN));

        try {
            new MSCabinetFile(new SeekableInMemoryByteChannel(data));
            fail("No exception thrown");
        } catch (IOException e) {
            assertEquals("MSCabinet file is corrupt: signature data (offset=8192, size=1024) after the end of the file", e.getMessage());
        }
    }
}
