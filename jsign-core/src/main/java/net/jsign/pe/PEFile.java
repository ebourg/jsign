/**
 * Copyright 2012 Emmanuel Bourg
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

package net.jsign.pe;

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
import net.jsign.asn1.authenticode.SpcPeImageData;

import static net.jsign.ChannelUtils.*;

/**
 * Portable Executable File.
 * 
 * This class is thread safe.
 * 
 * @see <a href="https://docs.microsoft.com/en-us/windows/win32/debug/pe-format">Microsoft PE and COFF Specification </a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PEFile implements Signable {

    /** The position of the PE header in the file */
    private final long peHeaderOffset;

    final SeekableByteChannel channel;

    /** Reusable buffer for reading bytes, words, dwords and qwords from the file */
    private final ByteBuffer valueBuffer = ByteBuffer.allocate(8);
    {
        valueBuffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Tells if the specified file is a Portable Executable file.
     *
     * @param file the file to check
     * @return <code>true</code> if the file is a Portable Executable, <code>false</code> otherwise
     * @throws IOException if an I/O error occurs
     * @since 3.0
     */
    public static boolean isPEFile(File file) throws IOException {
        if (!file.exists() || !file.isFile()) {
            return false;
        }
        
        try {
            PEFile peFile = new PEFile(file);
            peFile.close();
            return true;
        } catch (IOException e) {
            if (e.getMessage().contains("DOS header signature not found") || e.getMessage().contains("PE signature not found")) {
                return false;
            } else {
                throw e;
            }
        }
    }

    /**
     * Create a PEFile from the specified file.
     *
     * @param file the file to open
     * @throws IOException if an I/O error occurs
     */
    public PEFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
    }

    /**
     * Create a PEFile from the specified channel.
     *
     * @param channel the channel to read the file from
     * @throws IOException if an I/O error occurs
     * @since 2.0
     */
    public PEFile(SeekableByteChannel channel) throws IOException {
        this.channel = channel;
        
        try {
            // DOS Header
            read(0, 0, 2);
            if (valueBuffer.get() != 'M' || valueBuffer.get() != 'Z') {
                throw new IOException("DOS header signature not found");
            }

            // PE Header
            read(0x3C, 0, 4);
            peHeaderOffset = valueBuffer.getInt() & 0xFFFFFFFFL;
            read(peHeaderOffset, 0, 4);
            if (valueBuffer.get() != 'P' || valueBuffer.get() != 'E' || valueBuffer.get() != 0 || valueBuffer.get() != 0) {
                throw new IOException("PE signature not found as expected at offset 0x" + Long.toHexString(peHeaderOffset));
            }

        } catch (IOException e) {
            channel.close();
            throw e;
        }
    }

    public void save() {
    }

    /**
     * Closes the file
     *
     * @throws IOException if an I/O error occurs
     */
    public synchronized void close() throws IOException {
        channel.close();
    }

    synchronized int read(byte[] buffer, long base, int offset) throws IOException {
        channel.position(base + offset);
        return channel.read(ByteBuffer.wrap(buffer));
    }

    private void read(long base, int offset, int length) throws IOException {
        valueBuffer.limit(length);
        valueBuffer.clear();
        channel.position(base + offset);
        channel.read(valueBuffer);
        valueBuffer.rewind();
    }

    synchronized int readWord(long base, int offset) throws IOException {
        read(base, offset, 2);
        return valueBuffer.getShort() & 0xFFFF;
    }

    synchronized long readDWord(long base, int offset) throws IOException {
        read(base, offset, 4);
        return valueBuffer.getInt() & 0xFFFFFFFFL;
    }

    synchronized void write(long base, byte[] data) throws IOException {
        write(base, ByteBuffer.wrap(data));
    }

    synchronized void write(long base, ByteBuffer data) throws IOException {
        channel.position(base);
        while (data.hasRemaining()) {
            channel.write(data);
        }
    }

    PEFormat getFormat() throws IOException {
        return PEFormat.valueOf(readWord(peHeaderOffset, 24));
    }

    /**
     * The image file checksum.
     * 
     * @return the checksum of the image
     */
    long getCheckSum() throws IOException {
        return readDWord(peHeaderOffset, 88);
    }

    /**
     * Compute the checksum of the image file. The algorithm for computing
     * the checksum is incorporated into IMAGHELP.DLL.
     * 
     * @return the checksum of the image
     */
    synchronized long computeChecksum() throws IOException {
        PEImageChecksum checksum = new PEImageChecksum(peHeaderOffset + 88);
        
        ByteBuffer b = ByteBuffer.allocate(64 * 1024);

        channel.position(0);

        int len;
        while ((len = channel.read(b)) > 0) {
            b.flip();
            checksum.update(b.array(), 0, len);
        }
        
        return checksum.getValue();
    }

    synchronized void updateChecksum() throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt((int) computeChecksum());
        buffer.flip();

        write(peHeaderOffset + 88, buffer);
    }

    /**
     * The number of data-directory entries in the remainder of the optional
     * header. Each describes a location and size.
     * 
     * @return the number of data-directory entries
     */
    int getNumberOfRvaAndSizes() throws IOException {
        return (int) readDWord(peHeaderOffset, PEFormat.PE32.equals(getFormat()) ? 116 : 132);
    }

    int getDataDirectoryOffset() throws IOException {
        return (int) peHeaderOffset + (PEFormat.PE32.equals(getFormat()) ? 120 : 136);
    }

    /**
     * Returns the data directory of the specified type.
     * 
     * @param type the type of data directory
     * @return the data directory of the specified type
     */
    DataDirectory getDataDirectory(DataDirectoryType type) throws IOException {
        if (type.ordinal() >= getNumberOfRvaAndSizes()) {
            return null;
        } else {
            return new DataDirectory(this, type.ordinal());
        }
    }

    /**
     * Writes the certificate table. The data is either appended at the end of the file
     * or written over the previous certificate table.
     * 
     * @param data the content of the certificate table
     * @throws IOException if an I/O error occurs
     */
    synchronized void writeCertificateTable(byte[] data) throws IOException {
        DataDirectory directory = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        if (directory == null) {
            throw new IOException("No space allocated in the data directories index for the certificate table");
        }
        
        if (!directory.exists()) {
            // append the data directory at the end of the file on a 8-byte boundary
            long offset = channel.size() + (8 - channel.size() % 8) % 8;
            
            write(offset, data);
            
            // update the entry in the data directory table
            directory.write(offset, data.length);
            
        } else if (directory.isTrailing()) {
            // the data is at the end of the file, overwrite it
            write(directory.getVirtualAddress(), data);
            channel.truncate(directory.getVirtualAddress() + data.length); // trim the file if the data shrunk

            // update the size in the data directory table
            directory.write(directory.getVirtualAddress(), data.length);

        } else {
            throw new IOException("The certificate table isn't at the end of the file");
        }
        
        updateChecksum();
    }

    @Override
    public synchronized List<CMSSignedData> getSignatures() throws IOException {
        List<CMSSignedData> signatures = new ArrayList<>();
        
        for (CertificateTableEntry entry : getCertificateTable()) {
            try {
                CMSSignedData signedData = entry.getSignature();
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
            } catch (Exception | StackOverflowError e) {
                e.printStackTrace();
            }
        }
        
        return signatures;
    }

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        if (signature != null) {
            CertificateTableEntry entry = new CertificateTableEntry(signature);
            writeCertificateTable(entry.toBytes());

        } else if (getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE).exists()) {
            // erase the previous signature
            DataDirectory certificateTable = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
            channel.truncate(certificateTable.getVirtualAddress());
            certificateTable.write(0, 0);
        }
    }

    private synchronized List<CertificateTableEntry> getCertificateTable() throws IOException {
        List<CertificateTableEntry> entries = new ArrayList<>();
        DataDirectory certificateTable = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        
        if (certificateTable != null && certificateTable.exists()) {
            long position = certificateTable.getVirtualAddress();
            
            try {
                if (position < channel.size()) {
                    entries.add(new CertificateTableEntry(this, position));
                }
                
                // todo read the remaining entries (but Authenticode use only one, extra signatures are appended as a SPC_NESTED_SIGNATURE unauthenticated attribute)
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        return entries;
    }

    /**
     * Compute the digest of the file. The checksum field, the certificate
     * directory table entry and the certificate table are excluded from
     * the digest.
     * 
     * @param digestAlgorithm the digest algorithm to use
     * @return the digest of the file
     * @throws IOException if an I/O error occurs
     */
    @Override
    public synchronized byte[] computeDigest(DigestAlgorithm digestAlgorithm) throws IOException {
        MessageDigest digest = digestAlgorithm.getMessageDigest();

        long checksumLocation = peHeaderOffset + 88;
        
        DataDirectory certificateTable = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        
        // digest from the beginning to the checksum field (excluded)
        updateDigest(channel, digest, 0, checksumLocation);
        
        // skip the checksum field
        long position = checksumLocation + 4;
        
        // digest from the end of the checksum field to the beginning of the certificate table entry
        int certificateTableOffset = getDataDirectoryOffset() + 8 * DataDirectoryType.CERTIFICATE_TABLE.ordinal();
        updateDigest(channel, digest, position, certificateTableOffset);
        
        // skip the certificate entry
        position = certificateTableOffset + 8;
        
        // digest from the end of the certificate table entry to the beginning of the certificate table
        if (certificateTable != null && certificateTable.exists()) {
            certificateTable.check();
            updateDigest(channel, digest, position, certificateTable.getVirtualAddress());
            position = certificateTable.getVirtualAddress() + certificateTable.getSize();
        }
        
        // digest from the end of the certificate table to the end of the file
        updateDigest(channel, digest, position, channel.size());
        
        if (certificateTable == null || !certificateTable.exists()) {
            // if the file has never been signed before, update the digest as if the file was padded on a 8 byte boundary
            int paddingLength = (int) (8 - channel.size() % 8) % 8;
            digest.update(new byte[paddingLength]);
        }

        return digest.digest();
    }

    @Override
    public ASN1Object createIndirectData(DigestAlgorithm digestAlgorithm) throws IOException {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(digestAlgorithm.oid, DERNull.INSTANCE);
        DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, computeDigest(digestAlgorithm));
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());

        return new SpcIndirectDataContent(data, digestInfo);
    }
}
