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

package net.jsign.mscab;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;

class CFHeader {

    public final byte[] signature = new byte[4]; // u4
    public long csumHeader;     // u4
    public long cbCabinet;      // u4
    public long csumFolders;    // u4
    public long coffFiles;      // u4
    public long csumFiles;      // u4
    public byte versionMinor;   // u1
    public byte versionMajor;   // u1
    public int cFolders;        // u2
    public int cFiles;          // u2
    public int flags;           // u2
    public int setID;           // u2
    public int iCabinet;        // u2
    public int cbCFHeader;      // u2
    public byte cbCFFolder;     // u1
    public byte cbCFData;       // u1
    public byte[] abReserved;

    public CFHeader() {
    }

    public CFHeader(CFHeader origin) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(origin.getHeaderSize()).order(ByteOrder.LITTLE_ENDIAN);
        origin.write(buffer);
        buffer.flip();
        readHeaderFirst(buffer);
        readHeaderSecond(buffer);
        if (this.cbCFHeader > 0) {
            buffer.get(this.abReserved);
        }
    }

    public void read(SeekableByteChannel channel) throws IOException {
        if ((channel.size()) < 44) {
            throw new IOException("MSCabinet file too short");
        }
        ByteBuffer buffer = ByteBuffer.allocate(36).order(ByteOrder.LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();
        readHeaderFirst(buffer);
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            buffer.clear();
            buffer.limit(4);
            channel.read(buffer);
            buffer.flip();
            readHeaderSecond(buffer);
            if (this.cbCFHeader > 0) {
                ByteBuffer ab = ByteBuffer.wrap(this.abReserved);
                channel.read(ab);
            }
        }
    }

    private void readHeaderFirst(ByteBuffer buffer) throws IOException {
        buffer.get(this.signature);

        if (this.signature[0] != 'M' ||
                this.signature[1] != 'S' ||
                this.signature[2] != 'C' ||
                this.signature[3] != 'F') {
            throw new IOException("MSCabinet header signature not found");
        }

        this.csumHeader = buffer.getInt();  // u4
        this.cbCabinet = buffer.getInt();   // u4 H
        this.csumFolders = buffer.getInt(); // u4 H
        this.coffFiles = buffer.getInt();   // u4 H
        this.csumFiles = buffer.getInt();   // u4 H
        this.versionMinor = buffer.get();   // u1 H
        this.versionMajor = buffer.get();   // u1 H
        this.cFolders = buffer.getShort();  // u2 H
        this.cFiles = buffer.getShort();    // u2 H
        this.flags = buffer.getShort();     // u2 H
        this.setID = buffer.getShort();     // u2 H
        this.iCabinet = buffer.getShort();  // u2
        this.abReserved = null;
    }

    private void readHeaderSecond(ByteBuffer buffer) {
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            this.cbCFHeader = buffer.getShort(); // u2
            this.cbCFFolder = buffer.get(); // u1
            this.cbCFData = buffer.get(); // u1
            if (this.cbCFHeader > 0) {
                this.abReserved = new byte[this.cbCFHeader];
            } else {
                this.abReserved = null;
            }
        } else {
            this.cbCFHeader = 0;
            this.cbCFFolder = 0;
            this.cbCFData = 0;
            this.abReserved = null;
        }
    }

    public void write(ByteBuffer buffer) {
        buffer.put(this.signature);
        buffer.putInt((int) this.csumHeader);
        buffer.putInt((int) this.cbCabinet);
        buffer.putInt((int) this.csumFolders);
        buffer.putInt((int) this.coffFiles);
        buffer.putInt((int) this.csumFiles);
        buffer.put(this.versionMinor);
        buffer.put(this.versionMajor);
        buffer.putShort((short) this.cFolders);
        buffer.putShort((short) this.cFiles);
        buffer.putShort((short) this.flags);
        buffer.putShort((short) this.setID);
        buffer.putShort((short) this.iCabinet);
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            buffer.putShort((short) this.cbCFHeader);
            buffer.put(this.cbCFFolder);
            buffer.put(this.cbCFData);
            if (this.cbCFHeader > 0) {
                buffer.put(this.abReserved);
            }
        }
    }

    public int getHeaderSize() {
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            return 40 + this.cbCFHeader;
        } else {
            return 36;
        }
    }

    private static final int RESERVE_CNT_HDR_LEN = 4; // sizeof(USHORT) * 2

    public void headerDigestUpdate(MessageDigest digest) {
        ByteBuffer buffer = ByteBuffer.allocate(36).order(ByteOrder.LITTLE_ENDIAN);

        buffer.put(this.signature);
        buffer.putInt((int) this.cbCabinet);
        buffer.putInt((int) this.csumFolders);
        buffer.putInt((int) this.coffFiles);
        buffer.putInt((int) this.csumFiles);
        buffer.put(this.versionMinor);
        buffer.put(this.versionMajor);
        buffer.putShort((short) this.cFolders);
        buffer.putShort((short) this.cFiles);
        buffer.putShort((short) this.flags);
        buffer.putShort((short) this.setID);
        buffer.putShort((short) this.iCabinet);

        buffer.flip();
        digest.update(buffer);

        if (this.abReserved != null) {
            if (this.abReserved.length > RESERVE_CNT_HDR_LEN) {
                ByteBuffer reservedReader = ByteBuffer.wrap(this.abReserved).order(ByteOrder.LITTLE_ENDIAN);
                int cbJunk = reservedReader.getShort() & 0xFFFF;
                digest.update(this.abReserved, 0, 2);
                if (cbJunk > 0) {
                    digest.update(this.abReserved, RESERVE_CNT_HDR_LEN, cbJunk);
                }
            }
        }
    }

    public boolean hasSignature() {
        return this.abReserved != null;
    }

    public int getSigPos() {
        ByteBuffer buffer = ByteBuffer.wrap(this.abReserved).order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(4);
        return buffer.getInt();
    }

    public int getSigLen() {
        ByteBuffer buffer = ByteBuffer.wrap(this.abReserved).order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(8);
        return buffer.getInt();
    }
}
