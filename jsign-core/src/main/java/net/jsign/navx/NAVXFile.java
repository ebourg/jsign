/**
 * Copyright 2023 Emmanuel Bourg
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

package net.jsign.navx;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.DigestAlgorithm;
import net.jsign.Signable;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;
import net.jsign.asn1.authenticode.SpcAttributeTypeAndOptionalValue;
import net.jsign.asn1.authenticode.SpcIndirectDataContent;
import net.jsign.asn1.authenticode.SpcSipInfo;
import net.jsign.asn1.authenticode.SpcUuid;

import static net.jsign.ChannelUtils.*;

/**
 * Microsoft Dynamics 365 extension package (NAVX)
 *
 * @author Emmanuel Bourg
 * @since 5.1
 */
public class NAVXFile implements Signable {

    /** The channel used for in-memory signing */
    private final SeekableByteChannel channel;

    /** The underlying file */
    private File file;

    /** The file header */
    private final NAVXHeader header = new NAVXHeader();

    /**
     * Tells if the specified file is a NAVX file.
     *
     * @param file the file to check
     * @return <code>true</code> if the file is a NAVX file, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     */
    public static boolean isNAVXFile(File file) throws IOException {
        if (file.length() < NAVXHeader.SIZE) {
            return false;
        }

        // read the signature
        try (SeekableByteChannel channel = Files.newByteChannel(file.toPath(), StandardOpenOption.READ)) {
            ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            channel.read(buffer);
            buffer.flip();
            return buffer.getInt() == NAVXHeader.SIGNATURE;
        }
    }

    /**
     * Create a NAVXFile from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public NAVXFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
    }

    /**
     * Create a NAVXFile from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public NAVXFile(SeekableByteChannel channel) throws IOException {
        this.channel = channel;

        channel.position(0);
        header.read(channel);

        if (header.contentSize + NAVXHeader.SIZE > channel.size()) {
            throw new IOException("NAVX file is corrupt: invalid size in the header");
        }
    }

    @Override
    public byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        MessageDigest digest = digestAlgorithm.getMessageDigest();
        updateDigest(channel, digest, 0, getSignatureOffset());
        return digest.digest();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));

        SpcUuid uuid  = new SpcUuid("12341234-F804-0000-781D-123412341234");
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, new SpcSipInfo(1, uuid));

        return new SpcIndirectDataContent(data, digestInfo);
    }

    private int getSignatureOffset() {
        return NAVXHeader.SIZE + header.contentSize;
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        try {
            channel.position(getSignatureOffset());
            NAVXSignatureBlock signatureBlock = new NAVXSignatureBlock();
            signatureBlock.read(channel);
            CMSSignedData signedData = signatureBlock.signedData;
            if (signedData != null) {
                signatures.add(signedData);

                // look for nested signatures
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
        } catch (UnsupportedOperationException e) {
            // unsupported type, just skip
        } catch (Exception e) {
            e.printStackTrace();
        }

        return signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        NAVXSignatureBlock signatureBlock = new NAVXSignatureBlock();
        signatureBlock.signedData = signature;

        channel.position(getSignatureOffset());
        signatureBlock.write(channel);
        channel.truncate(channel.position());
    }

    @Override
    public void save() throws IOException {
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
