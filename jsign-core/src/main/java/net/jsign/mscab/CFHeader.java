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

public class CFHeader {
    public final byte[] signature = new byte[4]; // u4
    public long csumHeader = 0; // u4
    public long cbCabinet = 0; // u4
    public long csumFolders = 0; // u4
    public long coffFiles = 0; // u4
    public long csumFiles = 0; // u4
    public byte versionMinor = 0; // u1
    public byte versionMajor = 0; // u1
    public int cFolders = 0; // u2
    public int cFiles = 0; // u2
    public int flags = 0; // u2
    public int setID = 0; // u2
    public int iCabinet = 0; // u2
    public int cbCFHeader = 0; // u2
    public byte cbCFFolder = 0; // u1
    public byte cbCFData = 0; // u1
    public byte[] abReserved = null;

    public CFHeader() {
    }

    public CFHeader(CFHeader origin) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(origin.getHeaderSize())
                .order(ByteOrder.LITTLE_ENDIAN);
        origin.writeTo(bb);
        bb.flip();
        readHeaderFirst(bb);
        readHeaderSecond(bb);
        if (this.cbCFHeader > 0) {
            bb.get(this.abReserved);
        }
    }

    public void readFrom(SeekableByteChannel channel, long base) throws IOException {
        if ((channel.size() - base) < 44) {
            throw new IOException("MSCabinet file too short");
        }
        ByteBuffer bb = ByteBuffer.allocate(36)
                .order(ByteOrder.LITTLE_ENDIAN);
        channel.read(bb);
        bb.flip();
        readHeaderFirst(bb);
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            bb.clear();
            bb.limit(4);
            channel.read(bb);
            bb.flip();
            readHeaderSecond(bb);
            if (this.cbCFHeader > 0) {
                ByteBuffer ab = ByteBuffer.wrap(this.abReserved);
                channel.read(ab);
            }
        }
    }

    private void readHeaderFirst(ByteBuffer bb) throws IOException {
        bb.get(this.signature);

        if (    this.signature[0] != 'M' ||
                this.signature[1] != 'S' ||
                this.signature[2] != 'C' ||
                this.signature[3] != 'F') {
            throw new IOException("MSCabinet header signature not found");
        }

        this.csumHeader = bb.getInt(); // u4
        this.cbCabinet = bb.getInt(); // u4 H
        this.csumFolders = bb.getInt(); // u4 H
        this.coffFiles = bb.getInt(); // u4 H
        this.csumFiles = bb.getInt(); // u4 H
        this.versionMinor = bb.get(); // u1 H
        this.versionMajor = bb.get(); // u1 H
        this.cFolders = bb.getShort(); // u2 H
        this.cFiles = bb.getShort(); // u2 H
        this.flags = bb.getShort(); // u2 H
        this.setID = bb.getShort(); // u2 H
        this.iCabinet = bb.getShort(); // u2
        this.abReserved = null;
    }

    private void readHeaderSecond(ByteBuffer bb) throws IOException {
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            this.cbCFHeader = bb.getShort(); // u2
            this.cbCFFolder = bb.get(); // u1
            this.cbCFData = bb.get(); // u1
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

    public void writeTo(ByteBuffer bb) {
        bb.put(this.signature);
        bb.putInt((int)this.csumHeader);
        bb.putInt((int)this.cbCabinet);
        bb.putInt((int)this.csumFolders);
        bb.putInt((int)this.coffFiles);
        bb.putInt((int)this.csumFiles);
        bb.put(this.versionMinor);
        bb.put(this.versionMajor);
        bb.putShort((short)this.cFolders);
        bb.putShort((short)this.cFiles);
        bb.putShort((short)this.flags);
        bb.putShort((short)this.setID);
        bb.putShort((short)this.iCabinet);
        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(this.flags)) {
            bb.putShort((short)this.cbCFHeader);
            bb.put(this.cbCFFolder);
            bb.put(this.cbCFData);
            if (this.cbCFHeader > 0) {
                bb.put(this.abReserved);
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
    // See https://github.com/PubDom/Windows-Server-2003/blob/5c6fe3db626b63a384230a1aa6b92ac416b0765f/ds/security/cryptoapi/pkitrust/mssip32/sipobjcb.cpp
    public void headerDigestUpdate(MessageDigest digest) {
        ByteBuffer bb = ByteBuffer.allocate(36)
                .order(ByteOrder.LITTLE_ENDIAN);

        bb.put(this.signature);
        bb.putInt((int)this.cbCabinet);
        bb.putInt((int)this.csumFolders);
        bb.putInt((int)this.coffFiles);
        bb.putInt((int)this.csumFiles);
        bb.put(this.versionMinor);
        bb.put(this.versionMajor);
        bb.putShort((short)this.cFolders);
        bb.putShort((short)this.cFiles);
        bb.putShort((short)this.flags);
        bb.putShort((short)this.setID);
        bb.putShort((short)this.iCabinet);

        bb.flip();
        digest.update(bb);

        if (this.abReserved != null) {
            if (this.abReserved.length > RESERVE_CNT_HDR_LEN) {
                ByteBuffer reservedReader = ByteBuffer.wrap(this.abReserved)
                        .order(ByteOrder.LITTLE_ENDIAN);
                int cbJunk = reservedReader.getShort() & 0xffff;
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
        ByteBuffer bb = ByteBuffer.wrap(this.abReserved)
                .order(ByteOrder.LITTLE_ENDIAN);
        bb.position(4);
        return bb.getInt();
    }

    public int getSigLen() {
        ByteBuffer bb = ByteBuffer.wrap(this.abReserved)
                .order(ByteOrder.LITTLE_ENDIAN);
        bb.position(8);
        return bb.getInt();
    }

    private final ByteBuffer valueBuffer = ByteBuffer.allocate(8);
    {
        valueBuffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    private int read(SeekableByteChannel channel, byte[] buffer, long base, int offset) {
        try {
            channel.position(base + offset);
            return channel.read(ByteBuffer.wrap(buffer));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void read(SeekableByteChannel channel, long base, int offset, int length) {
        try {
            valueBuffer.limit(length);
            valueBuffer.clear();
            channel.position(base + offset);
            channel.read(valueBuffer);
            valueBuffer.rewind();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private int read(SeekableByteChannel channel, long base, int offset) {
        read(channel, base, offset, 1);
        return valueBuffer.get();
    }

    private int readWord(SeekableByteChannel channel, long base, int offset) {
        read(channel, base, offset, 2);
        return valueBuffer.getShort() & 0xFFFF;
    }

    private long readDWord(SeekableByteChannel channel, long base, int offset) {
        read(channel, base, offset, 4);
        return valueBuffer.getInt() & 0xFFFFFFFFL;
    }
}
