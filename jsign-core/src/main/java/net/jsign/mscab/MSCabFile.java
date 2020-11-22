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

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * MSCabinet File.
 *
 * This class is thread safe.
 *
 * @see <a href="http://download.microsoft.com/download/5/0/1/501ED102-E53F-4CE0-AA6B-B0F93629DDC6/Exchange/[MS-CAB].pdf">[MS-CAB]: Cabinet File Format</a>
 *
 * @author Joseph Lee
 * @since 3.2
 */
public class MSCabFile implements Signable, Closeable {
    private final CFHeader header = new CFHeader();
    private int sigpos = 0;
    private int siglen = 0;

    private File file;
    final SeekableByteChannel channel;

    /** Reusable buffer for reading bytes, words, dwords and qwords from the file */
    private final ByteBuffer valueBuffer = ByteBuffer.allocate(8);
    {
        valueBuffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Tells if the specified file is a MS Cabinet file.
     *
     * @param file the file to check
     * @return <code>true</code> if the file is a MS Cabinet, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     * @since 3.0
     */
    public static boolean isMSCabFile(File file) throws IOException {
        if (!file.exists() && !file.isFile()) {
            return false;
        }

        try {
            MSCabFile cabFile = new MSCabFile(file);
            cabFile.close();
            return true;
        } catch (IOException e) {
            if (e.getMessage().contains("MSCabinet header signature not found") || e.getMessage().contains("MSCabinet file too short")) {
                return false;
            } else {
                throw e;
            }
        }
    }

    /**
     * Create a MSCabFile from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public MSCabFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
        this.file = file;
    }

    /**
     * Create a MSCabFile from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     * @since 2.0
     */
    public MSCabFile(SeekableByteChannel channel) throws IOException {
        this.channel = channel;

        channel.position(0);
        header.readFrom(channel, 0);

        if (header.reserved1 != 0) {
            throw new IOException("MSCabinet file is corrupt: invalid reserved field");
        }

        if (CFHeaderFlag.RESERVE_PRESENT.checkFrom(header.flags)) {
            ByteBuffer bb = ByteBuffer.wrap(header.abReserved)
                    .order(ByteOrder.LITTLE_ENDIAN);
            if (header.cbCFHeader != 20) {
                throw new IOException("MSCabinet file is corrupt: addition header size is " + header.cbCFHeader);
            }

            int reserved = bb.getInt();
            if (reserved != 0x00100000) {
                throw new IOException("MSCabinet file is corrupt: addition abReserved is " + reserved);
            }

            sigpos = bb.getInt();
            siglen = bb.getInt();

            if (sigpos < channel.size() && (sigpos + siglen) > channel.size()) {
                throw new IOException("MSCabinet file is corrupt: " + String.format(
                        "Addition data offset=%d, size=%d", sigpos, siglen
                ));
            }
        }
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    private byte[] readNullTerminatedString(SeekableByteChannel channel) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte singleChar;
            ByteBuffer bbtmp = ByteBuffer.allocate(1);
            do {
                bbtmp.clear();
                bbtmp.limit(1);
                channel.read(bbtmp);
                bbtmp.flip();
                singleChar = bbtmp.array()[0];
                bos.write(singleChar);
            } while (singleChar != 0);
            return bos.toByteArray();
        }
    }

    @Override
    public synchronized byte[] computeDigest(MessageDigest digest) throws IOException {
        CFHeader modifiedHeader = new CFHeader(header);
        if (!CFHeaderFlag.RESERVE_PRESENT.checkFrom(header.flags)) {
            ByteBuffer bb = ByteBuffer.allocate(20)
                    .order(ByteOrder.LITTLE_ENDIAN);

            modifiedHeader.cbCFHeader = 20;
            modifiedHeader.cbCabinet += 24;
            modifiedHeader.coffFiles += 24;
            modifiedHeader.flags |= CFHeaderFlag.RESERVE_PRESENT.getValue();

            bb.putInt(0x00100000);
            bb.putInt((int)modifiedHeader.cbCabinet); // size of cab file
            bb.putInt(0); // size of signature asn1 der
            bb.putInt(0);
            bb.putInt(0);

            modifiedHeader.abReserved = bb.array();
        }
        modifiedHeader.headerDigestUpdate(digest);

        ByteBuffer bbtmp = ByteBuffer.allocate(4096).order(ByteOrder.LITTLE_ENDIAN);
        int off = header.getHeaderSize();
        channel.position(off);

        if (CFHeaderFlag.NEXT_CABINET.checkFrom(header.flags)) {
            byte[] szCabinetNext = readNullTerminatedString(channel);
            byte[] szDiskNext = readNullTerminatedString(channel);
            digest.update(szCabinetNext);
            digest.update(szDiskNext);
            off += szCabinetNext.length + szDiskNext.length;
        }

        for (int i = 0; i < header.cFolders; i++) {
            bbtmp.clear();
            bbtmp.limit(8);
            channel.read(bbtmp);
            bbtmp.flip();
            if (!CFHeaderFlag.RESERVE_PRESENT.checkFrom(header.flags)) {
                int a = bbtmp.getInt();
                int b = bbtmp.getInt();
                a += 24;
                bbtmp.clear();
                bbtmp.putInt(a);
                bbtmp.putInt(b);
                digest.update(bbtmp.array(), 0, 8);
            } else {
                digest.update(bbtmp.array(), 0, 8);
            }
            off += 8;
        }

        long endPosition = header.hasSignature() ? header.getSigPos() : channel.size();
        channel.position(off);
        while(channel.position() < endPosition) {
            long remaining = endPosition - channel.position();
            bbtmp.clear();
            if (remaining < bbtmp.capacity()) {
                bbtmp.limit((int)remaining);
            }
            channel.read(bbtmp);
            bbtmp.flip();
            digest.update(bbtmp);
        }

        return digest.digest();
    }

    /**
     * Compute the checksum of the file using the specified digest algorithm.
     *
     * @param algorithm the digest algorithm, typically SHA1
     * @return the checksum of the file
     * @throws IOException if an I/O error occurs
     */
    public byte[] computeDigest(DigestAlgorithm algorithm) throws IOException {
        return computeDigest(algorithm.getMessageDigest());
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_CAB_DATA_OBJID, new SpcPeImageData());

        return new SpcIndirectDataContent(data, digestInfo);
    }

    @Override
    public synchronized List<CMSSignedData> getSignatures() throws IOException {
        ArrayList<CMSSignedData> signatures = new ArrayList<>();
        try {
            if (siglen > 0) {
                byte[] buffer = new byte[siglen];
                channel.position(sigpos);
                channel.read(ByteBuffer.wrap(buffer));

                CMSSignedData signedData;
                signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(buffer).readObject()));
                signatures.add(signedData);

                SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();
                AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
                if (unsignedAttributes != null) {
                    Attribute nestedSignatures = unsignedAttributes.get(AuthenticodeObjectIdentifiers.SPC_NESTED_SIGNATURE_OBJID);
                    if (nestedSignatures != null) {
                        for (ASN1Encodable nestedSignature : nestedSignatures.getAttrValues()) {
                            signatures.add(new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(nestedSignature)));
                        }
                    }
                }
            }
        } catch (CMSException e) {
            throw new IOException(e);
        }
        return signatures;
    }

    private void copyAllTo(WritableByteChannel dest) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(1048576);
        channel.position(0);

        while (channel.position() < channel.size()) {
            bb.clear();
            channel.read(bb);
            bb.flip();
            dest.write(bb);
        }
    }

    private void copyFixedSize(SeekableByteChannel dest, SeekableByteChannel src, long copySize) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(1048576);
        long remaining = copySize;
        long destOffset = dest.position();
        long srcOffset = src.position();
        while (remaining > 0) {
            int avail = (int)Math.min(remaining, bb.capacity());
            bb.clear();
            bb.limit(avail);

            src.position(srcOffset);
            src.read(bb);
            bb.flip();

            dest.position(destOffset);
            dest.write(bb);
            remaining -= bb.position();
            srcOffset += bb.position();
            destOffset += bb.position();
        }
    }

    @Override
    public synchronized void setSignature(CMSSignedData signature) throws IOException {
        byte[] content = signature.toASN1Structure().getEncoded("DER");

        ByteBuffer abReserveWriter = ByteBuffer.allocate(20)
                .order(ByteOrder.LITTLE_ENDIAN);
        boolean modified = false;

        File backupFile = null;
        SeekableByteChannel backupChannel = null;
        SeekableByteChannel readChannel = channel;
        long readOffset = header.getHeaderSize();
        long writeOffset;

        try {
            if (!CFHeaderFlag.RESERVE_PRESENT.checkFrom(header.flags)) {
                backupFile = File.createTempFile("tmp", ".cab");
                backupChannel = (Files.newByteChannel(backupFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
                copyAllTo(backupChannel);
                readChannel = backupChannel;

                modified = true;

                header.cbCFHeader = 20;
                header.cbCabinet += 24;
                header.coffFiles += 24;
                header.flags |= CFHeaderFlag.RESERVE_PRESENT.getValue();

                abReserveWriter.putInt(0x00100000);
                abReserveWriter.putInt((int) header.cbCabinet); // size of cab file
                abReserveWriter.putInt(content.length); // size of signature asn1 der
                abReserveWriter.putInt(0);
                abReserveWriter.putInt(0);
            } else {
                ByteBuffer bb = ByteBuffer.wrap(header.abReserved)
                        .order(ByteOrder.LITTLE_ENDIAN);
                abReserveWriter.putInt(bb.getInt());
                bb.getInt(); abReserveWriter.putInt((int) header.cbCabinet); // size of cab file
                bb.getInt(); abReserveWriter.putInt(content.length); // size of signature asn1 der
                abReserveWriter.putInt(bb.getInt());
                abReserveWriter.putInt(bb.getInt());
            }

            header.abReserved = abReserveWriter.array();

            channel.position(0);
            {
                ByteBuffer bb = ByteBuffer.allocate(header.getHeaderSize())
                        .order(ByteOrder.LITTLE_ENDIAN);
                header.writeTo(bb);
                bb.flip();
                channel.write(bb);
            }
            writeOffset = channel.position();

            if (CFHeaderFlag.NEXT_CABINET.checkFrom(header.flags)) {
                readChannel.position(readOffset);
                byte[] szCabinetNext = readNullTerminatedString(readChannel);
                byte[] szDiskNext = readNullTerminatedString(readChannel);
                channel.write(ByteBuffer.wrap(szCabinetNext));
                channel.write(ByteBuffer.wrap(szDiskNext));
                readOffset += szCabinetNext.length + szDiskNext.length;
                writeOffset += szCabinetNext.length + szDiskNext.length;
            }

            ByteBuffer readBuf = ByteBuffer.allocate(8)
                    .order(ByteOrder.LITTLE_ENDIAN);
            ByteBuffer writeBuf = ByteBuffer.allocate(8)
                    .order(ByteOrder.LITTLE_ENDIAN);

            if (modified) {
                for (int i = 0; i < header.cFolders; i++) {
                    readBuf.clear();
                    readChannel.position(readOffset);
                    readChannel.read(readBuf);
                    readBuf.flip();

                    int a = readBuf.getInt();
                    int b = readBuf.getInt();
                    a += 24;
                    writeBuf.putInt(a);
                    writeBuf.putInt(b);

                    writeBuf.flip();
                    channel.position(writeOffset);
                    channel.write(writeBuf);
                    readOffset += 8;
                    writeOffset += 8;
                }
            }

            long payloadSize = (readChannel.size() - readOffset) - siglen;
            copyFixedSize(channel, readChannel, payloadSize);

            channel.write(ByteBuffer.wrap(content));

            if (channel.position() < channel.size()) {
                channel.truncate(channel.position());
            }

            sigpos = (int)header.cbCabinet;
            siglen = content.length;
        } finally {
            if (backupChannel != null) {
                backupChannel.close();
            }
            if (backupFile != null) {
                backupFile.delete();
            }
        }
    }

    @Override
    public void save() throws IOException {
    }

    /**
     * Print detailed informations about the PE file.
     *
     * @param out the output stream where the info is printed
     */
    public void printInfo(OutputStream out) {
        printInfo(new PrintWriter(out, true));
    }

    /**
     * Print detailed informations about the PE file.
     *
     * @param out the output writer where the info is printed
     */
    public void printInfo(PrintWriter out) {
        if (file != null) {
            out.println("CAB File");
            out.println("  Name:          " + file.getName());
            out.println("  Size:          " + file.length());
            out.println("  Last Modified: " + new Date(file.lastModified()));
            out.println();
        }
    }
}
