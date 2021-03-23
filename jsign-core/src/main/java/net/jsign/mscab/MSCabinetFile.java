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

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

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

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;

/**
 * Microsoft Cabinet File.
 *
 * This class is thread safe.
 *
 * @see <a href="http://download.microsoft.com/download/5/0/1/501ED102-E53F-4CE0-AA6B-B0F93629DDC6/Exchange/[MS-CAB].pdf">[MS-CAB]: Cabinet File Format</a>
 *
 * @author Joseph Lee
 * @since 3.2
 */
public class MSCabinetFile implements Signable, Closeable {

    private final CFHeader header = new CFHeader();
    private int sigpos;
    private int siglen;

    private final SeekableByteChannel channel;

    /**
     * Tells if the specified file is a MS Cabinet file.
     *
     * @param file the file to check
     * @return <code>true</code> if the file is a MS Cabinet, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     */
    public static boolean isMSCabinetFile(File file) throws IOException {
        if (!file.exists() && !file.isFile()) {
            return false;
        }

        try {
            MSCabinetFile cabFile = new MSCabinetFile(file);
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
     * Create a MSCabinetFile from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public MSCabinetFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
    }

    /**
     * Create a MSCabinetFile from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public MSCabinetFile(SeekableByteChannel channel) throws IOException {
        this.channel = channel;

        channel.position(0);
        header.read(channel);

        if (header.csumHeader != 0) {
            throw new IOException("MSCabinet file is corrupt: invalid reserved field in the header");
        }

        if (header.isReservePresent()) {
            ByteBuffer buffer = ByteBuffer.wrap(header.abReserved).order(ByteOrder.LITTLE_ENDIAN);
            if (header.cbCFHeader != CFHeader.RESERVE_SIZE) {
                throw new IOException("MSCabinet file is corrupt: additional header size is " + header.cbCFHeader);
            }

            int reserved = buffer.getInt();
            if (reserved != CFHeader.RESERVE_HEADER) {
                throw new IOException("MSCabinet file is corrupt: additional abReserved is " + reserved);
            }

            sigpos = buffer.getInt();
            siglen = buffer.getInt();

            if (sigpos < channel.size() && (sigpos + siglen) > channel.size()) {
                throw new IOException("MSCabinet file is corrupt: Additional data offset=" + sigpos + ", size=" + siglen);
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
            ByteBuffer buffer = ByteBuffer.allocate(1);
            do {
                buffer.clear();
                buffer.limit(1);
                channel.read(buffer);
                buffer.flip();
                singleChar = buffer.array()[0];
                bos.write(singleChar);
            } while (singleChar != 0);
            return bos.toByteArray();
        }
    }

    @Override
    public synchronized byte[] computeDigest(MessageDigest digest) throws IOException {
        CFHeader modifiedHeader = new CFHeader(header);
        if (!header.isReservePresent()) {
            ByteBuffer buffer = ByteBuffer.allocate(CFHeader.RESERVE_SIZE).order(ByteOrder.LITTLE_ENDIAN);

            modifiedHeader.cbCFHeader = CFHeader.RESERVE_SIZE;
            modifiedHeader.cbCabinet += 4 + CFHeader.RESERVE_SIZE;
            modifiedHeader.coffFiles += 4 + CFHeader.RESERVE_SIZE;
            modifiedHeader.flags |= CFHeader.FLAG_RESERVE_PRESENT;

            buffer.putInt(CFHeader.RESERVE_HEADER);
            buffer.putInt((int) modifiedHeader.cbCabinet); // offset of the signature (end of file)
            buffer.putInt(0); // size of the signature
            buffer.putLong(0); // filler

            modifiedHeader.abReserved = buffer.array();
        }
        modifiedHeader.headerDigestUpdate(digest);

        ByteBuffer buffer = ByteBuffer.allocate(4096).order(ByteOrder.LITTLE_ENDIAN);
        channel.position(header.getHeaderSize());

        if (header.hasPreviousCabinet()) {
            digest.update(readNullTerminatedString(channel)); // szCabinetPrev
            digest.update(readNullTerminatedString(channel)); // szDiskPrev
        }

        if (header.hasNextCabinet()) {
            digest.update(readNullTerminatedString(channel)); // szCabinetNext
            digest.update(readNullTerminatedString(channel)); // szDiskNext
        }

        for (int i = 0; i < header.cFolders; i++) {
            CFFolder folder = CFFolder.read(channel);
            if (!header.isReservePresent()) {
                folder.coffCabStart += 4 + CFHeader.RESERVE_SIZE;
            }
            folder.digest(digest);
        }

        long endPosition = header.hasSignature() ? header.getSigPos() : channel.size();
        while (channel.position() < endPosition) {
            long remaining = endPosition - channel.position();
            buffer.clear();
            if (remaining < buffer.capacity()) {
                buffer.limit((int) remaining);
            }
            int readBytes = channel.read(buffer);
            if (readBytes < 0) {
                throw new IOException("Unknown file format");
            }
            buffer.flip();
            digest.update(buffer);
        }

        return digest.digest();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm.getMessageDigest()));
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_CAB_DATA_OBJID, new SpcPeImageData());

        return new SpcIndirectDataContent(data, digestInfo);
    }

    @Override
    public synchronized List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();
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
        ByteBuffer buffer = ByteBuffer.allocate(1024 * 1024);
        channel.position(0);

        while (channel.position() < channel.size()) {
            buffer.clear();
            channel.read(buffer);
            buffer.flip();
            dest.write(buffer);
        }
    }

    private void copyFixedSize(SeekableByteChannel dest, SeekableByteChannel src, long copySize) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(1024 * 1024);
        long remaining = copySize;
        long destOffset = dest.position();
        long srcOffset = src.position();
        while (remaining > 0) {
            int avail = (int) Math.min(remaining, buffer.capacity());
            buffer.clear();
            buffer.limit(avail);

            src.position(srcOffset);
            src.read(buffer);
            buffer.flip();

            dest.position(destOffset);
            dest.write(buffer);
            remaining -= buffer.position();
            srcOffset += buffer.position();
            destOffset += buffer.position();
        }
    }

    @Override
    public synchronized void setSignature(CMSSignedData signature) throws IOException {
        byte[] content = signature.toASN1Structure().getEncoded("DER");

        ByteBuffer abReserveWriter = ByteBuffer.allocate(CFHeader.RESERVE_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        boolean modified = false;

        File backupFile = null;
        SeekableByteChannel backupChannel = null;
        SeekableByteChannel readChannel = channel;
        readChannel.position(header.getHeaderSize());

        try {
            if (!header.isReservePresent()) {
                backupFile = File.createTempFile("tmp", ".cab");
                backupChannel = Files.newByteChannel(backupFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE);
                copyAllTo(backupChannel);
                readChannel = backupChannel;
                readChannel.position(header.getHeaderSize());

                modified = true;

                header.cbCFHeader = CFHeader.RESERVE_SIZE;
                header.cbCabinet += 4 + CFHeader.RESERVE_SIZE;
                header.coffFiles += 4 + CFHeader.RESERVE_SIZE;
                header.flags |= CFHeader.FLAG_RESERVE_PRESENT;

                abReserveWriter.putInt(CFHeader.RESERVE_HEADER);
                abReserveWriter.putInt((int) header.cbCabinet); // offset of the signature (end of file)
                abReserveWriter.putInt(content.length); // size of the signature
                abReserveWriter.putLong(0); // filler
            } else {
                ByteBuffer buffer = ByteBuffer.wrap(header.abReserved).order(ByteOrder.LITTLE_ENDIAN);
                abReserveWriter.putInt(buffer.getInt());
                buffer.getInt();
                abReserveWriter.putInt((int) header.cbCabinet); // offset of the signature (end of file)
                buffer.getInt();
                abReserveWriter.putInt(content.length); // size of the signature
                abReserveWriter.putLong(buffer.getLong()); // filler
            }

            header.abReserved = abReserveWriter.array();

            channel.position(0);
            {
                ByteBuffer buffer = ByteBuffer.allocate(header.getHeaderSize()).order(ByteOrder.LITTLE_ENDIAN);
                header.write(buffer);
                buffer.flip();
                channel.write(buffer);
            }

            if (header.hasPreviousCabinet()) {
                channel.write(ByteBuffer.wrap(readNullTerminatedString(readChannel))); // szCabinetPrev
                channel.write(ByteBuffer.wrap(readNullTerminatedString(readChannel))); // szDiskPrev
            }

            if (header.hasNextCabinet()) {
                channel.write(ByteBuffer.wrap(readNullTerminatedString(readChannel))); // szCabinetNext
                channel.write(ByteBuffer.wrap(readNullTerminatedString(readChannel))); // szDiskNext
            }

            if (modified) {
                for (int i = 0; i < header.cFolders; i++) {
                    CFFolder folder = CFFolder.read(readChannel);
                    folder.coffCabStart += 4 + CFHeader.RESERVE_SIZE;

                    folder.write(channel);
                }
            }

            long payloadSize = (readChannel.size() - readChannel.position()) - siglen;
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
    public void save() {
    }
}
