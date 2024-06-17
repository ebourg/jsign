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

import static net.jsign.ChannelUtils.*;

/**
 * Cabinet File Header structure (CFHEADER):
 *
 * <pre>
 * signature                           4 bytes  (0x4643534d: 'MSCF')
 * reserved1 (former header checksum)  4 bytes
 * size of the cabinet file            4 bytes
 * reserved2 (former folders checksum) 4 bytes
 * offset  of the first CFFILE entry   4 bytes
 * reserved3 (former files checksum)   4 bytes
 * minor format version                1 byte
 * major format version                1 byte
 * number of CFFOLDER entries          2 bytes
 * number of CFFILE entries            2 bytes
 * flags                               2 bytes
 * set identifier                      2 bytes
 * cabinet sequential number           2 bytes
 * size of per-cabinet reserved area   2 bytes  (optional)
 * size of per-folder reserved area    1 byte   (optional)
 * size of per-datablock reserved area 1 byte   (optional)
 * reserved area                       (variable size, optional)
 * file name of the previous cabinet   (variable size, optional)
 * media with the previous cabinet     (variable size, optional)
 * file name of the next cabinet       (variable size, optional)
 * media with the next cabinet         (variable size, optional)
 * </pre>
 *
 * @since 4.0
 */
class CFHeader {

    public static final int SIGNATURE = 0x4643534d; // MSCF

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
    public short cbCFFolder;    // u1
    public short cbCFData;      // u1
    public byte[] abReserved;
    public byte[] szCabinetPrev;
    public byte[] szDiskPrev;
    public byte[] szCabinetNext;
    public byte[] szDiskNext;

    /**
     * FLAG_PREV_CABINET is set if this cabinet file is not the first in a set
     * of cabinet files. When this bit is set, the szCabinetPrev and szDiskPrev
     * fields are present in this CFHEADER.
     */
    public static final int FLAG_PREV_CABINET    = 0b00000001;

    /**
     * FLAG_NEXT_CABINET is set if this cabinet file is not the last in a set
     * of cabinet files. When this bit is set, the szCabinetNext and szDiskNext
     * fields are present in this CFHEADER.
     */
    public static final int FLAG_NEXT_CABINET    = 0b00000010;

    /**
     * FLAG_RESERVE_PRESENT is set if this cabinet file contains any reserved
     * fields. When this bit is set, the cbCFHeader, cbCFFolder, and cbCFData
     * fields are present in this CFHEADER.
     */
    public static final int FLAG_RESERVE_PRESENT = 0b00000100;

    /** Base size of the header (with no optional fields) */
    public static final int BASE_SIZE = 36;

    public CFHeader() {
    }

    public CFHeader(CFHeader header) {
        this.csumHeader = header.csumHeader;
        this.cbCabinet = header.cbCabinet;
        this.csumFolders = header.csumFolders;
        this.coffFiles = header.coffFiles;
        this.csumFiles = header.csumFiles;
        this.versionMinor = header.versionMinor;
        this.versionMajor = header.versionMajor;
        this.cFolders = header.cFolders;
        this.cFiles = header.cFiles;
        this.flags = header.flags;
        this.setID = header.setID;
        this.iCabinet = header.iCabinet;
        this.cbCFHeader = header.cbCFHeader;
        this.cbCFFolder = header.cbCFFolder;
        this.cbCFData = header.cbCFData;
        this.abReserved = header.abReserved != null ? header.abReserved.clone() : null;
        this.szCabinetPrev = header.szCabinetPrev;
        this.szDiskPrev = header.szDiskPrev;
        this.szCabinetNext = header.szCabinetNext;
        this.szDiskNext = header.szDiskNext;
    }

    public void read(SeekableByteChannel channel) throws IOException {
        if ((channel.size()) < BASE_SIZE + CFFolder.BASE_SIZE) {
            throw new IOException("MSCabinet file too short");
        }
        ByteBuffer buffer = ByteBuffer.allocate(BASE_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        channel.read(buffer);
        buffer.flip();

        int signature = buffer.getInt();
        if (signature != SIGNATURE) {
            throw new IOException("Invalid MSCabinet header signature " + String.format("0x%04x", signature & 0xFFFFFFFFL));
        }

        this.csumHeader = buffer.getInt() & 0xFFFFFFFFL;  // u4
        this.cbCabinet = buffer.getInt() & 0xFFFFFFFFL;   // u4 H
        this.csumFolders = buffer.getInt() & 0xFFFFFFFFL; // u4 H
        this.coffFiles = buffer.getInt() & 0xFFFFFFFFL;   // u4 H
        this.csumFiles = buffer.getInt() & 0xFFFFFFFFL;   // u4 H
        this.versionMinor = buffer.get();                 // u1 H
        this.versionMajor = buffer.get();                 // u1 H
        this.cFolders = buffer.getShort() & 0xFFFF;       // u2 H
        this.cFiles = buffer.getShort() & 0xFFFF;         // u2 H
        this.flags = buffer.getShort() & 0xFFFF;          // u2 H
        this.setID = buffer.getShort();                   // u2 H
        this.iCabinet = buffer.getShort() & 0xFFFF;       // u2
        this.abReserved = null;

        if (isReservePresent()) {
            buffer.clear();
            buffer.limit(4);
            channel.read(buffer);
            buffer.flip();

            this.cbCFHeader = buffer.getShort() & 0xFFFF;    // u2
            this.cbCFFolder = (short) (buffer.get() & 0xFF); // u1
            this.cbCFData = (short) (buffer.get() & 0xFF);   // u1
            if (this.cbCFHeader > 0) {
                this.abReserved = new byte[this.cbCFHeader];
                channel.read(ByteBuffer.wrap(this.abReserved));
            }
        }

        if (hasPreviousCabinet()) {
            szCabinetPrev = readNullTerminatedString(channel);
            szDiskPrev = readNullTerminatedString(channel);
        }

        if (hasNextCabinet()) {
            szCabinetNext = readNullTerminatedString(channel);
            szDiskNext = readNullTerminatedString(channel);
        }
    }

    public void write(ByteBuffer buffer) {
        buffer.putInt(SIGNATURE);
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
        if (isReservePresent()) {
            buffer.putShort((short) this.cbCFHeader);
            buffer.put((byte) this.cbCFFolder);
            buffer.put((byte) this.cbCFData);
            if (this.cbCFHeader > 0) {
                buffer.put(this.abReserved);
            }
        }
        if (hasPreviousCabinet()) {
            buffer.put(szCabinetPrev);
            buffer.put(szDiskPrev);
        }
        if (hasNextCabinet()) {
            buffer.put(szCabinetNext);
            buffer.put(szDiskNext);
        }
    }

    public int getHeaderSize() {
        int size = BASE_SIZE;
        if (isReservePresent()) {
            size += 4 + this.cbCFHeader;
        }
        if (hasPreviousCabinet()) {
            size += szCabinetPrev.length;
            size += szDiskPrev.length;
        }
        if (hasNextCabinet()) {
            size += szCabinetNext.length;
            size += szDiskNext.length;
        }
        return size;
    }

    public void headerDigestUpdate(MessageDigest digest) {
        ByteBuffer buffer = ByteBuffer.allocate(BASE_SIZE).order(ByteOrder.LITTLE_ENDIAN);

        buffer.putInt(SIGNATURE);
        // the checksum of the header is skipped
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
            digest.update(abReserved, 0, 2); // 0x0000
        }

        if (hasPreviousCabinet()) {
            digest.update(szCabinetPrev);
            digest.update(szDiskPrev);
        }

        if (hasNextCabinet()) {
            digest.update(szCabinetNext);
            digest.update(szDiskNext);
        }
    }

    public boolean hasPreviousCabinet() {
        return (FLAG_PREV_CABINET & flags) != 0;
    }

    public boolean hasNextCabinet() {
        return (FLAG_NEXT_CABINET & flags) != 0;
    }

    public boolean isReservePresent() {
        return (FLAG_RESERVE_PRESENT & flags) != 0;
    }

    public boolean hasSignature() {
        return this.abReserved != null;
    }

    public CABSignature getSignature() {
        return abReserved != null ? new CABSignature(abReserved) : null;
    }
}
