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

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSSignedData;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.SignatureUtils;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcPeImageData;

import static net.jsign.ChannelUtils.*;

/**
 * Microsoft Cabinet File.
 *
 * This class is thread safe.
 *
 * @see <a href="http://download.microsoft.com/download/5/0/1/501ED102-E53F-4CE0-AA6B-B0F93629DDC6/Exchange/%5BMS-CAB%5D.pdf">[MS-CAB]: Cabinet File Format</a>
 *
 * @author Joseph Lee
 * @since 4.0
 */
public class MSCabinetFile implements Signable {

    private final CFHeader header = new CFHeader();

    private final SeekableByteChannel channel;

    /**
     * Tells if the specified file is a MS Cabinet file.
     *
     * @param file the file to check
     * @return <code>true</code> if the file is a MS Cabinet, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     */
    public static boolean isMSCabinetFile(File file) throws IOException {
        if (!file.exists() || !file.isFile()) {
            return false;
        }

        try {
            MSCabinetFile cabFile = new MSCabinetFile(file);
            cabFile.close();
            return true;
        } catch (IOException e) {
            if (e.getMessage().contains("Invalid MSCabinet header signature") || e.getMessage().contains("MSCabinet file too short")) {
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

        if (header.hasSignature() && header.reserve.structure2.length == CABSignature.SIZE) {
            CABSignature cabsig = new CABSignature(header.reserve.structure2);
            if (cabsig.offset < channel.size() && (cabsig.offset + cabsig.length) > channel.size() || cabsig.offset > channel.size()) {
                throw new IOException("MSCabinet file is corrupt: signature data (offset=" + cabsig.offset + ", size=" + cabsig.length + ") after the end of the file");
            }

            if (header.cbCabinet != cabsig.offset) {
                throw new IOException("MSCabinet file is corrupt: the declared size of the file (" + header.cbCabinet + ") doesn't match the offset of the signature (" + cabsig.offset + ")");
            }

            if (header.cbCabinet + cabsig.length != channel.size()) {
                throw new IOException("MSCabinet file is corrupt: the declared size of the file (" + header.cbCabinet + ") and the size of the signature (" + cabsig.length + ") are inconsistent with the actual size of the file (" + channel.size() + ")");
            }
        }
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    @Override
    public synchronized byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        MessageDigest digest = digestAlgorithm.getMessageDigest();

        CFReserve modifiedReserve = new CFReserve();
        modifiedReserve.minSize = header.cbCFHeader;
        if (header.reserve != null) {
            modifiedReserve.structure1 = header.reserve.structure1;
        }
        modifiedReserve.structure2 = new byte[CABSignature.SIZE];

        CFHeader modifiedHeader = new CFHeader(header);
        modifiedHeader.setReserve(modifiedReserve);
        modifiedHeader.headerDigestUpdate(digest);

        int shift = modifiedHeader.getHeaderSize() - header.getHeaderSize();

        channel.position(header.getHeaderSize());

        for (int i = 0; i < header.cFolders; i++) {
            CFFolder folder = CFFolder.read(channel);
            folder.coffCabStart += shift;
            folder.digest(digest);
            updateDigest(channel, digest, channel.position(), channel.position() + header.cbCFFolder);
        }

        long endPosition = header.cbCabinet;
        updateDigest(channel, digest, channel.position(), endPosition);

        return digest.digest();
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
        if (header.hasSignature()) {
            if (header.reserve.structure2.length == CABSignature.SIZE) {
                CABSignature cabsig = new CABSignature(header.reserve.structure2);
                if (cabsig.offset > 0 && cabsig.length > 0 && cabsig.length < channel.size()) {
                    byte[] buffer = new byte[(int) cabsig.length];
                    channel.position(cabsig.offset);
                    channel.read(ByteBuffer.wrap(buffer));

                    return SignatureUtils.getSignatures(buffer);
                }
            } else {
                return SignatureUtils.getSignatures(header.reserve.structure2);
            }
        }

        return Collections.emptyList();
    }

    @Override
    public synchronized void setSignature(CMSSignedData signature) throws IOException {
        if (signature == null && !header.hasSignature()) {
            return;
        }

        byte[] content = signature != null ? signature.toASN1Structure().getEncoded("DER") : new byte[0];

        int previousSize = header.getHeaderSize();

        CFReserve reserve = new CFReserve();
        reserve.minSize = header.cbCFHeader;
        if (header.reserve != null) {
            reserve.structure1 = header.reserve.structure1;
        }

        if (content.length > 0) {
            reserve.structure2 = new byte[CABSignature.SIZE];

            header.setReserve(reserve);

            CABSignature cabsig = new CABSignature();
            cabsig.offset = header.cbCabinet;
            cabsig.length = content.length;

            reserve.structure2 = cabsig.array();
        } else {
            reserve.structure2 = new byte[0];

            header.setReserve(reserve);
        }

        int currentSize = header.getHeaderSize();
        int shift = currentSize - previousSize;

        if (shift > 0) {
            insert(channel, previousSize, new byte[shift]);
        } else if (shift < 0) {
            delete(channel, previousSize + shift, -shift);
        }

        // rewrite the header
        header.write(channel);

        if (shift != 0) {
            // shift the start offset of the CFFOLDER structures
            for (int i = 0; i < header.cFolders; i++) {
                long position = channel.position();
                CFFolder folder = CFFolder.read(channel);
                folder.coffCabStart += shift;

                channel.position(position);
                folder.write(channel);
            }
        }

        // write the signature
        channel.position(header.cbCabinet);
        channel.write(ByteBuffer.wrap(content));

        // shrink the file if the new signature is shorter
        if (channel.position() < channel.size()) {
            channel.truncate(channel.position());
        }
    }

    @Override
    public void save() {
    }
}
