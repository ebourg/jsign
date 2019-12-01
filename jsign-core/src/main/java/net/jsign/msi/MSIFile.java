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
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.DocumentNode;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSDocument;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.util.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

/**
 * A Microsoft Installer package.
 * 
 * @author Emmanuel Bourg
 * @since 3.0
 */
public class MSIFile implements Closeable {

    private static final long MSI_HEADER = 0xD0CF11E0A1B11AE1L;

    private static final String DIGITAL_SIGNATURE_ENTRY_NAME = "\u0005DigitalSignature";
    private static final String MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME = "\u0005MsiDigitalSignatureEx";

    private final POIFSFileSystem fs;
    private SeekableByteChannel channel;

    /**
     * Tells if the specified file is a MSI file.
     */
    public static boolean isMSIFile(File file) throws IOException {
        try (DataInputStream in = new DataInputStream(new FileInputStream(file))) {
            return in.readLong() == MSI_HEADER;
        }
    }

    /**
     * Create a MSIFile from the specified file.
     */
    public MSIFile(File file) throws IOException {
        this.fs = new POIFSFileSystem(file, false);
    }

    /**
     * Create a MSIFile from the specified channel.
     */
    public MSIFile(final SeekableByteChannel channel) throws IOException {
        this.channel = channel;
        InputStream in = new FilterInputStream(Channels.newInputStream(channel)) {
            public void close() { }
        };
        this.fs = new POIFSFileSystem(in);
    }

    public void close() throws IOException {
        fs.close();
        if (channel != null) {
            channel.close();
        }
    }

    /**
     * Tells if the MSI file has an extended signature (MsiDigitalSignatureEx)
     * containing a hash of the streams metadata (name, size, date).
     */
    public boolean hasExtendedSignature() {
        try {
            fs.getRoot().getEntry(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME);
            return true;
        } catch (FileNotFoundException e) {
            return false;
        }
    }

    private List<DocumentNode> getSortedEntries() {
        List<DocumentNode> entries = new ArrayList<>();
        
        append(fs.getRoot(), entries);
        
        return entries;
    }

    private void append(DirectoryNode node, List<DocumentNode> entries) {
        Map<MSIStreamName, Entry> sortedEntries = new TreeMap<>();
        for (Entry entry : node) {
            sortedEntries.put(new MSIStreamName(entry.getName()), entry);
        }

        for (Entry entry : sortedEntries.values()) {
            if (entry.isDocumentEntry()) {
                entries.add((DocumentNode) entry);
            } else if (entry.isDirectoryEntry()) {
                append((DirectoryNode) entry, entries);
            }
        }
    }

    public byte[] computeDigest(MessageDigest digest) throws IOException {
        // hash the entries
        for (DocumentNode entry : getSortedEntries()) {
            String name = new MSIStreamName(entry.getName()).decode();
            if (name.equals(DIGITAL_SIGNATURE_ENTRY_NAME) || name.equals(MSI_DIGITAL_SIGNATURE_EX_ENTRY_NAME)) {
                continue;
            }

            POIFSDocument document = new POIFSDocument(entry);
            long remaining = entry.getSize();
            for (ByteBuffer buffer : document) {
                int limit = buffer.limit();
                buffer.limit((int) Math.min(remaining, limit));
                digest.update(buffer);
                remaining -= limit;
            }
        }

        // hash the package ClassID, in serialized form
        byte[] classId = new byte[16];
        fs.getRoot().getStorageClsid().write(classId, 0);
        digest.update(classId);
        
        return digest.digest();
    }

    /**
     * Returns the authenticode signatures on the file.
     */
    public List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();

        try {
            DocumentEntry digitalSignature = (DocumentEntry) fs.getRoot().getEntry(DIGITAL_SIGNATURE_ENTRY_NAME);
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

    /**
     * Sets the signature of the file, overwriting the previous one.
     */
    public void setSignature(CMSSignedData signature) throws IOException {
        byte[] signatureBytes = signature.toASN1Structure().getEncoded("DER");
        fs.getRoot().createOrUpdateDocument(DIGITAL_SIGNATURE_ENTRY_NAME, new ByteArrayInputStream(signatureBytes));
    }

    /**
     * Saves the file.
     */
    public void save() throws IOException {
        if (channel == null) {
            fs.writeFilesystem();
        } else {
            channel.position(0);
            fs.writeFilesystem(Channels.newOutputStream(channel));
            channel.truncate(channel.position());
        }
    }
}
