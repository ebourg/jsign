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

package net.jsign.msi;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;

import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.DocumentNode;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSDocument;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.poifs.property.DirectoryProperty;
import org.apache.poi.poifs.property.DocumentProperty;
import org.apache.poi.poifs.property.Property;
import org.apache.poi.util.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
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

import static org.apache.poi.poifs.common.POIFSConstants.*;

/**
 * A Microsoft Installer package.
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class MSIFile implements Signable {

    private static final long MSI_HEADER = 0xD0CF11E0A1B11AE1L;

    private static final String DIGITAL_SIGNATURE_ENTRY_NAME = "\u0005DigitalSignature";
    private static final String MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME = "\u0005MsiDigitalSignatureEx";

    /**
     * The POI filesystem used for reading the file. A separate filesystem has
     * to be used because POI maps the file in memory in read/write mode and
     * this leads to OOM errors when the file is parsed.
     * See https://github.com/ebourg/jsign/issues/82 for more info.
     */
    private POIFSFileSystem fsRead;

    /** The POI filesystem used for writing to the file */
    private POIFSFileSystem fsWrite;

    /** The channel used for in-memory signing */
    private SeekableByteChannel channel;

    /** The underlying file */
    private File file;

    /**
     * Tells if the specified file is a MSI file.
     * 
     * @param file the file to check
     * @return <code>true</code> if the file is a Microsoft installer, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     */
    public static boolean isMSIFile(File file) throws IOException {
        if (file.length() < 8) {
            return false;
        }
        try (DataInputStream in = new DataInputStream(new FileInputStream(file))) {
            return in.readLong() == MSI_HEADER;
        }
    }

    /**
     * Create a MSIFile from the specified file.
     * 
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public MSIFile(File file) throws IOException {
        this.file = file;
        try {
            this.fsRead = new POIFSFileSystem(file, true);
            this.fsWrite = new POIFSFileSystem(file, false);
        } catch (IndexOutOfBoundsException | IllegalStateException | ClassCastException e) {
            throw new IOException("MSI file format error", e);
        }
    }

    /**
     * Create a MSIFile from the specified channel.
     * 
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     */
    public MSIFile(final SeekableByteChannel channel) throws IOException {
        this.channel = channel;
        InputStream in = new FilterInputStream(Channels.newInputStream(channel)) {
            public void close() { }
        };
        this.fsRead = new POIFSFileSystem(in);
        this.fsWrite = fsRead;
    }

    /**
     * Closes the file
     *
     * @throws IOException if an I/O error occurs
     */
    public void close() throws IOException {
        try (POIFSFileSystem fsRead = this.fsRead; POIFSFileSystem fsWrite = this.fsWrite; SeekableByteChannel channel = this.channel) {
            // do nothing
        }
    }

    /**
     * Tells if the MSI file has an extended signature (MsiDigitalSignatureEx)
     * containing a hash of the streams metadata (name, size, date).
     * 
     * @return <code>true</code> if the file has a MsiDigitalSignatureEx stream, <code>false</code> otherwise
     */
    public boolean hasExtendedSignature() {
        try {
            fsRead.getRoot().getEntry(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME);
            return true;
        } catch (FileNotFoundException e) {
            return false;
        }
    }

    @Override
    public byte[] computeDigest(MessageDigest digest) throws IOException {
        try {
            // hash the MsiDigitalSignatureEx entry if there is one
            if (fsRead.getRoot().hasEntry(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME)) {
                Entry msiDigitalSignatureExEntry = fsRead.getRoot().getEntry(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME);
                POIFSDocument msiDigitalSignatureExDocument = new POIFSDocument((DocumentNode) msiDigitalSignatureExEntry);
                updateDigest(digest, msiDigitalSignatureExDocument);
            }

            computeDigest(digest, fsRead.getPropertyTable().getRoot());

            return digest.digest();
        } catch (IndexOutOfBoundsException | IllegalArgumentException | IllegalStateException | NoSuchElementException e) {
            throw new IOException("MSI file format error", e);
        }
    }

    private void computeDigest(MessageDigest digest, DirectoryProperty node) {
        Map<MSIStreamName, Property> sortedEntries = new TreeMap<>();
        for (Property child : node) {
            sortedEntries.put(new MSIStreamName(child.getName()), child);
        }

        for (Property property : sortedEntries.values()) {
            if (!property.isDirectory()) {
                String name = new MSIStreamName(property.getName()).decode();
                if (name.equals(DIGITAL_SIGNATURE_ENTRY_NAME) || name.equals(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME)) {
                    continue;
                }

                POIFSDocument document = new POIFSDocument((DocumentProperty) property, fsRead);
                updateDigest(digest, document);
            } else {
                computeDigest(digest, (DirectoryProperty) property);
            }
        }

        // hash the package ClassID, in serialized form
        byte[] classId = new byte[16];
        node.getStorageClsid().write(classId, 0);
        digest.update(classId);
    }

    private void updateDigest(MessageDigest digest, POIFSDocument document) {
        long remaining = document.getSize();
        for (ByteBuffer buffer : document) {
            int size = buffer.remaining();
            buffer.limit(buffer.position() + (int) Math.min(remaining, size));
            digest.update(buffer);
            remaining -= size;
        }
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm.getMessageDigest()));

        SpcUuid uuid = new SpcUuid("F1100C00-0000-0000-C000-000000000046");
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_SIPINFO_OBJID, new SpcSipInfo(1, uuid));

        return new SpcIndirectDataContent(data, digestInfo);
    }

    @Override
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        try {
            DocumentEntry digitalSignature = (DocumentEntry) fsRead.getRoot().getEntry(DIGITAL_SIGNATURE_ENTRY_NAME);
            if (digitalSignature != null) {
                byte[] signatureBytes = IOUtils.toByteArray(new DocumentInputStream(digitalSignature));
                try {
                    CMSSignedData signedData = new CMSSignedData((CMSProcessable) null, ContentInfo.getInstance(new ASN1InputStream(signatureBytes).readObject()));
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
                } catch (UnsupportedOperationException e) {
                    // unsupported type, just skip
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (FileNotFoundException e) {
        }
        
        return signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        if (signature != null) {
            byte[] signatureBytes = signature.toASN1Structure().getEncoded("DER");
            try {
                fsWrite.getRoot().createOrUpdateDocument(DIGITAL_SIGNATURE_ENTRY_NAME, new ByteArrayInputStream(signatureBytes));
            } catch (IndexOutOfBoundsException e) {
                throw new IOException("MSI file format error", e);
            }
        } else {
            // remove the signature
            if (fsWrite.getRoot().hasEntry(DIGITAL_SIGNATURE_ENTRY_NAME)) {
                fsWrite.getRoot().getEntry(DIGITAL_SIGNATURE_ENTRY_NAME).delete();
            }
            if (fsWrite.getRoot().hasEntry(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME)) {
                fsWrite.getRoot().getEntry(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME).delete();
            }
        }
    }

    @Override
    public void save() throws IOException {
        // get the number of directory sectors to be written in the header to work around https://bz.apache.org/bugzilla/show_bug.cgi?id=66590
        ByteBuffer directorySectorsCount = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        directorySectorsCount.putInt(fsWrite.getPropertyTable().countBlocks()).flip();
        int version = fsWrite.getBigBlockSize() == SMALLER_BIG_BLOCK_SIZE ? 3 : 4;

        if (channel == null) {
            fsWrite.writeFilesystem();

            // update the number of directory sectors in the header
            if (version == 4) {
                fsWrite.close();
                try (RandomAccessFile in = new RandomAccessFile(file, "rw")) {
                    in.seek(0x28);
                    in.write(directorySectorsCount.array());
                }
                try {
                    fsWrite = new POIFSFileSystem(file, false);
                } catch (IndexOutOfBoundsException e) {
                    throw new IOException("MSI file format error", e);
                }
            }

            fsRead.close();
            try {
                fsRead = new POIFSFileSystem(file, true);
            } catch (IndexOutOfBoundsException e) {
                throw new IOException("MSI file format error", e);
            }
        } else {
            channel.position(0);
            fsWrite.writeFilesystem(Channels.newOutputStream(channel));
            channel.truncate(channel.position());

            // update the number of directory sectors in the header
            if (version == 4) {
                channel.position(0x28);
                channel.write(directorySectorsCount);
            }
        }
    }
}
