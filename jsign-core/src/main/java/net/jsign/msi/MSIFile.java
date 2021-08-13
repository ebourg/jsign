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
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
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

/**
 * A Microsoft Installer package.
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class MSIFile implements Signable, Closeable {

    private static final long MSI_HEADER = 0xD0CF11E0A1B11AE1L;

    private static final String DIGITAL_SIGNATURE_ENTRY_NAME = "\u0005DigitalSignature";
    private static final String MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME = "\u0005MsiDigitalSignatureEx";

    /**
     * The POI filesystem used for reading the file. A separate filesystem has
     * to be used because POI maps the file in memory in read/write mode and
     * this leads to OOM errors when the file is parsed.
     * See https://github.com/ebourg/jsign/issues/82 for more info.
     */
    private final POIFSFileSystem fsRead;

    /** The POI filesystem used for writing to the file */
    private final POIFSFileSystem fsWrite;

    /** The channel used for in-memory signing */
    private SeekableByteChannel channel;

    /**
     * Tells if the specified file is a MSI file.
     * 
     * @param file the file to check
     * @return <code>true</code> if the file is a Microsoft installer, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     */
    public static boolean isMSIFile(File file) throws IOException {
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
        this.fsRead = new POIFSFileSystem(file, true);
        this.fsWrite = new POIFSFileSystem(file, false);
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

    private List<Property> getSortedProperties() {
        List<Property> entries = new ArrayList<>();
        
        append(fsRead.getPropertyTable().getRoot(), entries);
        
        return entries;
    }

    private void append(DirectoryProperty node, List<Property> entries) {
        Map<MSIStreamName, Property> sortedEntries = new TreeMap<>();
        for (Property entry : node) {
            sortedEntries.put(new MSIStreamName(entry.getName()), entry);
        }

        for (Property property : sortedEntries.values()) {
            if (!property.isDirectory()) {
                entries.add(property);
            } else {
                append((DirectoryProperty) property, entries);
            }
        }
    }

    @Override
    public byte[] computeDigest(MessageDigest digest) {
        // hash the entries
        for (Property property : getSortedProperties()) {
            String name = new MSIStreamName(property.getName()).decode();
            if (name.equals(DIGITAL_SIGNATURE_ENTRY_NAME) || name.equals(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME)) {
                continue;
            }

            POIFSDocument document = new POIFSDocument((DocumentProperty) property, fsRead);
            long remaining = document.getSize();
            for (ByteBuffer buffer : document) {
                int size = buffer.remaining();
                buffer.limit(buffer.position() + (int) Math.min(remaining, size));
                digest.update(buffer);
                remaining -= size;
            }
        }

        // hash the package ClassID, in serialized form
        byte[] classId = new byte[16];
        fsRead.getRoot().getStorageClsid().write(classId, 0);
        digest.update(classId);
        
        return digest.digest();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) {
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
        byte[] signatureBytes = signature.toASN1Structure().getEncoded("DER");
        fsWrite.getRoot().createOrUpdateDocument(DIGITAL_SIGNATURE_ENTRY_NAME, new ByteArrayInputStream(signatureBytes));
    }

    @Override
    public void save() throws IOException {
        if (channel == null) {
            fsWrite.writeFilesystem();
        } else {
            channel.position(0);
            fsWrite.writeFilesystem(Channels.newOutputStream(channel));
            channel.truncate(channel.position());
        }
    }
}
