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

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

/**
 * Portable Executable File.
 * 
 * This class is thread safe.
 * 
 * @see <a href="http://msdn.microsoft.com/en-us/library/windows/hardware/gg463119.aspx">Microsoft PE and COFF Specification </a>
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class PEFile implements Closeable {

    /** The position of the PE header in the file */
    private final long peHeaderOffset;

    private File file;
    final SeekableByteChannel channel;

    /** Reusable buffer for reading bytes, words, dwords and qwords from the file */
    private final ByteBuffer valueBuffer = ByteBuffer.allocate(8);
    {
        valueBuffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Create a PEFile from the specified file.
     *
     * @param file
     * @throws IOException
     */
    public PEFile(File file) throws IOException {
        this(Files.newByteChannel(file.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE));
        this.file = file;
    }

    /**
     * Create a PEFile from the specified channel.
     *
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

    public synchronized void close() throws IOException {
        channel.close();
    }

    synchronized int read(byte[] buffer, long base, int offset) {
        try {
            channel.position(base + offset);
            return channel.read(ByteBuffer.wrap(buffer));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void read(long base, int offset, int length) {
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

    synchronized int read(long base, int offset) {
        read(base, offset, 1);
        return valueBuffer.get();
    }

    synchronized int readWord(long base, int offset) {
        read(base, offset, 2);
        return valueBuffer.getShort() & 0xFFFF;
    }

    synchronized long readDWord(long base, int offset) {
        read(base, offset, 4);
        return valueBuffer.getInt() & 0xFFFFFFFFL;
    }

    synchronized long readQWord(long base, int offset) {
        read(base, offset, 8);
        return valueBuffer.getLong();
    }

    synchronized void write(long base, byte[] data) {
        try {
            channel.position(base);
            channel.write(ByteBuffer.wrap(data));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public MachineType getMachineType() {
        return MachineType.valueOf(readWord(peHeaderOffset, 4));
    }

    /**
     * The number of sections. This indicates the size of the section table,
     * which immediately follows the headers.
     */
    public int getNumberOfSections() {
        return readWord(peHeaderOffset, 6);
    }

    /**
     * The low 32 bits of the number of seconds since 00:00 January 1, 1970
     * (a C runtime time_t value), that indicates when the file was created.
     */
    public Date getTimeDateStamp() {
        return new Date(1000 * readDWord(peHeaderOffset, 8));
    }

    /**
     * The file offset of the COFF symbol table, or zero if no COFF symbol table
     * is present. This value should be zero for an image because COFF debugging
     * information is deprecated.
     */
    public long getPointerToSymbolTable() {
        return readDWord(peHeaderOffset, 12);
    }

    /**
     * The number of entries in the symbol table. This data can be used to
     * locate the string table, which immediately follows the symbol table.
     * This value should be zero for an image because COFF debugging
     * information is deprecated.
     */
    public long getNumberOfSymbols() {
        return readDWord(peHeaderOffset, 16);
    }

    /**
     * The size of the optional header, which is required for executable files
     * but not for object files. This value should be zero for an object file.
     */
    public int getSizeOfOptionalHeader() {
        return readWord(peHeaderOffset, 20);
    }

    /**
     * The flags that indicate the attributes of the file. 
     */
    public int getCharacteristics() {
        return readWord(peHeaderOffset, 22);
    }
    
    public PEFormat getFormat() {
        return PEFormat.valueOf(readWord(peHeaderOffset, 24));
    }

    /**
     * The linker major version number.
     */
    public int getMajorLinkerVersion() {
        return read(peHeaderOffset, 26);
    }

    /**
     * The linker minor version number.
     */
    public int getMinorLinkerVersion() {
        return read(peHeaderOffset, 27);
    }

    /**
     * The size of the code (text) section, or the sum of all code sections
     * if there are multiple sections.
     */
    public long getSizeOfCode() {
        return readDWord(peHeaderOffset, 28);
    }

    /**
     * The size of the initialized data section, or the sum of all such
     * sections if there are multiple data sections.
     */
    public long getSizeOfInitializedData() {
        return readDWord(peHeaderOffset, 32);
    }

    /**
     * The size of the uninitialized data section (BSS), or the sum of all such
     * sections if there are multiple BSS sections.
     */
    public long getSizeOfUninitializedData() {
        return readDWord(peHeaderOffset, 36);
    }

    /**
     * The address of the entry point relative to the image base when the
     * executable file is loaded into memory. For program images, this is the
     * starting address. For device drivers, this is the address of the
     * initialization function. An entry point is optional for DLLs. When no
     * entry point is present, this field must be zero.
     */
    public long getAddressOfEntryPoint() {
        return readDWord(peHeaderOffset, 40);
    }

    /**
     * The address that is relative to the image base of the beginning-of-code 
     * section when it is loaded into memory.
     */
    public long getBaseOfCode() {
        return readDWord(peHeaderOffset, 44);
    }

    /**
     * The address that is relative to the image base of the beginning-of-data 
     * section when it is loaded into memory (PE32 only).
     */
    public long getBaseOfData() {
        if (PEFormat.PE32.equals(getFormat())) {
            return readDWord(peHeaderOffset, 48);
        } else {
            return 0;
        }
    }

    /**
     * The preferred address of the first byte of image when loaded into memory;
     * must be a multiple of 64 K. The default for DLLs is 0x10000000. The default
     * for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000,
     * Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
     */
    public long getImageBase() {
        if (PEFormat.PE32.equals(getFormat())) {
            return readDWord(peHeaderOffset, 52);
        } else {
            return readQWord(peHeaderOffset, 48);
        }
    }

    /**
     * The alignment (in bytes) of sections when they are loaded into memory.
     * It must be greater than or equal to FileAlignment. The default is the
     * page size for the architecture.
     */
    public long getSectionAlignment() {
        return readDWord(peHeaderOffset, 56);
    }

    /**
     * The alignment factor (in bytes) that is used to align the raw data of
     * sections in the image file. The value should be a power of 2 between
     * 512 and 64 K, inclusive. The default is 512. If the SectionAlignment
     * is less than the architecture?s page size, then FileAlignment must
     * match SectionAlignment.
     */
    public long getFileAlignment() {
        return readDWord(peHeaderOffset, 60);
    }

    /**
     * The major version number of the required operating system.
     */
    public int getMajorOperatingSystemVersion() {
        return readWord(peHeaderOffset, 64);
    }

    /**
     * The minor version number of the required operating system.
     */
    public int getMinorOperatingSystemVersion() {
        return readWord(peHeaderOffset, 66);
    }

    /**
     * The major version number of the image.
     */
    public int getMajorImageVersion() {
        return readWord(peHeaderOffset, 68);
    }

    /**
     * The minor version number of the image.
     */
    public int getMinorImageVersion() {
        return readWord(peHeaderOffset, 70);
    }

    /**
     * The major version number of the subsystem.
     */
    public int getMajorSubsystemVersion() {
        return readWord(peHeaderOffset, 72);
    }

    /**
     * The minor version number of the subsystem.
     */
    public int getMinorSubsystemVersion() {
        return readWord(peHeaderOffset, 74);
    }

    /**
     * Reserved, must be zero.
     */
    public long getWin32VersionValue() {
        return readDWord(peHeaderOffset, 76);
    }

    /**
     * The size (in bytes) of the image, including all headers, as the image
     * is loaded in memory. It must be a multiple of SectionAlignment.
     */
    public long getSizeOfImage() {
        return readDWord(peHeaderOffset, 80);
    }

    /**
     * The combined size of an MS DOS stub, PE header, and section headers
     * rounded up to a multiple of FileAlignment.
     */
    public long getSizeOfHeaders() {
        return readDWord(peHeaderOffset, 84);
    }

    /**
     * The image file checksum.
     */
    public long getCheckSum() {
        return readDWord(peHeaderOffset, 88);
    }

    /**
     * Compute the checksum of the image file. The algorithm for computing
     * the checksum is incorporated into IMAGHELP.DLL.
     */
    public synchronized long computeChecksum() {
        PEImageChecksum checksum = new PEImageChecksum(peHeaderOffset + 88);
        
        ByteBuffer b = ByteBuffer.allocate(64 * 1024);
        
        try {
            channel.position(0);
            
            int len;
            while ((len = channel.read(b)) > 0) {
                checksum.update(b.array(), 0, len);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        
        return checksum.getValue();
    }

    public synchronized void updateChecksum() {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt((int) computeChecksum());
        
        try {
            channel.position(peHeaderOffset + 88);
            channel.write(buffer);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The subsystem that is required to run this image.
     */
    public Subsystem getSubsystem() {
        return Subsystem.valueOf(readWord(peHeaderOffset, 92));
    }

    public int getDllCharacteristics() {
        return readWord(peHeaderOffset, 94);
    }

    /**
     * The size of the stack to reserve. Only SizeOfStackCommit is committed;
     * the rest is made available one page at a time until the reserve size is reached.
     */
    public long getSizeOfStackReserve() {
        if (PEFormat.PE32.equals(getFormat())) {
            return readDWord(peHeaderOffset, 96);
        } else {
            return readQWord(peHeaderOffset, 96);
        }
    }

    /**
     * The size of the stack to commit.
     */
    public long getSizeOfStackCommit() {
        if (PEFormat.PE32.equals(getFormat())) {
            return readDWord(peHeaderOffset, 100);
        } else {
            return readQWord(peHeaderOffset, 104);
        }
    }

    /**
     * The size of the local heap space to reserve. Only SizeOfHeapCommit is
     * committed; the rest is made available one page at a time until the
     * reserve size is reached.
     */
    public long getSizeOfHeapReserve() {
        if (PEFormat.PE32.equals(getFormat())) {
            return readDWord(peHeaderOffset, 104);
        } else {
            return readQWord(peHeaderOffset, 112);
        }
    }

    /**
     * The size of the local heap space to commit.
     */
    public long getSizeOfHeapCommit() {
        if (PEFormat.PE32.equals(getFormat())) {
            return readDWord(peHeaderOffset, 108);
        } else {
            return readQWord(peHeaderOffset, 120);
        }
    }

    /**
     * Reserved, must be zero.
     */
    public long getLoaderFlags() {
        return readDWord(peHeaderOffset, PEFormat.PE32.equals(getFormat()) ? 112 : 128);
    }

    /**
     * The number of data-directory entries in the remainder of the optional
     * header. Each describes a location and size.
     */
    public int getNumberOfRvaAndSizes() {
        return (int) readDWord(peHeaderOffset, PEFormat.PE32.equals(getFormat()) ? 116 : 132);
    }

    int getDataDirectoryOffset() {
        return (int) peHeaderOffset + (PEFormat.PE32.equals(getFormat()) ? 120 : 136);
    }

    /**
     * Returns the data directory of the specified type.
     */
    public DataDirectory getDataDirectory(DataDirectoryType type) {
        if (type.ordinal() >= getNumberOfRvaAndSizes()) {
            return null;
        } else {
            return new DataDirectory(this, type.ordinal());
        }
    }

    /**
     * Writes the data directory of the specified type. The data is either appended
     * at the end of the file or written over the previous data of the same type if
     * there is enough space.
     * 
     * @param type the type of the data directory
     * @param data the content of the data directory
     */
    public synchronized void writeDataDirectory(DataDirectoryType type, byte[] data) throws IOException {
        DataDirectory directory = getDataDirectory(type);
        
        if (!directory.exists()) {
            // append the data directory at the end of the file
            long offset = channel.size();
            
            channel.position(offset);
            channel.write(ByteBuffer.wrap(data));
            
            // update the entry in the data directory table
            directory.write(offset, data.length);
            
        } else {
            if (data.length == directory.getSize()) {
                // same size as before, just overwrite
                channel.position(directory.getVirtualAddress());
                channel.write(ByteBuffer.wrap(data));

            } else if (data.length < directory.getSize() && type != DataDirectoryType.CERTIFICATE_TABLE) {
                // the new data is smaller, erase and rewrite in-place
                // this doesn't work with the certificate table since it changes the file digest
                directory.erase();
                channel.position(directory.getVirtualAddress());
                channel.write(ByteBuffer.wrap(data));
                
                // update the size in the data directory table
                directory.write(directory.getVirtualAddress(), data.length);

            } else if (directory.isTrailing()) {
                // the data is at the end of the file, overwrite it
                channel.position(directory.getVirtualAddress());
                channel.write(ByteBuffer.wrap(data));
                channel.truncate(directory.getVirtualAddress() + data.length); // trim the file if the data shrunk
                
                // update the size in the data directory table
                directory.write(directory.getVirtualAddress(), data.length);

            } else {
                if (type == DataDirectoryType.CERTIFICATE_TABLE) {
                    throw new IOException("The certificate table isn't at the end of the file and can't be moved without invalidating the signature");
                }
                
                // the new data is larger, erase and relocate it at the end
                directory.erase();
                
                long offset = channel.size();
                
                channel.position(offset);
                channel.write(ByteBuffer.wrap(data));
                
                // update the entry in the data directory table
                directory.write(offset, data.length);
            }
        }
        
        updateChecksum();
    }

    /**
     * Returns the authenticode signatures on the file.
     */
    public synchronized List<CMSSignedData> getSignatures() {
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
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        return signatures;
    }

    private synchronized List<CertificateTableEntry> getCertificateTable() {
        List<CertificateTableEntry> entries = new ArrayList<>();
        DataDirectory certificateTable = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        
        if (certificateTable != null && certificateTable.exists()) {
            long position = certificateTable.getVirtualAddress();
            
            try {
                entries.add(new CertificateTableEntry(this, position));
                
                // todo read the remaining entries (but Authenticode use only one, extra signatures are appended as a SPC_NESTED_SIGNATURE unauthenticated attribute)
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        return entries;
    }

    public synchronized List<Section> getSections() {
        List<Section> sections = new ArrayList<>();
        int sectionTableOffset = getDataDirectoryOffset() + 8 * getNumberOfRvaAndSizes();
        
        for (int i = 0; i < getNumberOfSections(); i++) {
            sections.add(new Section(this, sectionTableOffset + 40 * i));
        }
        
        return sections;
    }

    /**
     * Print detailed informations about the PE file.
     */
    public void printInfo(OutputStream out) {
        printInfo(new PrintWriter(out, true));
    }

    /**
     * Print detailed informations about the PE file.
     */
    public void printInfo(PrintWriter out) {
        if (file != null) {
            out.println("PE File");
            out.println("  Name:          " + file.getName());
            out.println("  Size:          " + file.length());
            out.println("  Last Modified: " + new Date(file.lastModified()));
            out.println();
        }
        
        out.println("PE Header");
        out.println("  Machine:                    " + getMachineType());
        out.println("  Number of sections:         " + getNumberOfSections());
        out.println("  Timestamp:                  " + getTimeDateStamp());
        out.println("  Pointer to symbol table:    0x" + Long.toHexString(getPointerToSymbolTable()));
        out.println("  Number of symbols:          " + getNumberOfSymbols());
        out.println("  Size of optional header:    " + getSizeOfOptionalHeader());
        out.println("  Characteristics:            0x" + Long.toBinaryString(getCharacteristics()));
        out.println();
        
        out.println("Optional Header");
        PEFormat format = getFormat();
        out.println("  PE Format:                  0x" + Integer.toHexString(format.value) + " (" + format.label + ")");
        out.println("  Linker version:             " + getMajorLinkerVersion() + "." + getMinorLinkerVersion());
        out.println("  Size of code:               " + getSizeOfCode());
        out.println("  Size of initialized data:   " + getSizeOfInitializedData());
        out.println("  Size of uninitialized data: " + getSizeOfUninitializedData());
        out.println("  Address of entry point:     0x" + Long.toHexString(getAddressOfEntryPoint()));
        out.println("  Base of code:               0x" + Long.toHexString(getBaseOfCode()));
        if (PEFormat.PE32.equals(getFormat())) {
            out.println("  Base of data:               0x" + Long.toHexString(getBaseOfData()));
        }
        out.println("  Image base:                 0x" + Long.toHexString(getImageBase()));
        out.println("  Section alignment:          " + getSectionAlignment());
        out.println("  File alignment:             " + getFileAlignment());
        out.println("  Operating system version:   " + getMajorOperatingSystemVersion() + "." + getMinorOperatingSystemVersion());
        out.println("  Image version:              " + getMajorImageVersion() + "." + getMinorImageVersion());
        out.println("  Subsystem version:          " + getMajorSubsystemVersion() + "." + getMinorSubsystemVersion());
        out.println("  Size of image:              " + getSizeOfImage());
        out.println("  Size of headers:            " + getSizeOfHeaders());
        out.println("  Checksum:                   0x" + Long.toHexString(getCheckSum()));
        out.println("  Checksum (computed):        0x" + Long.toHexString(computeChecksum()));
        out.println("  Subsystem:                  " + getSubsystem());
        out.println("  DLL characteristics:        0x" + Long.toBinaryString(getDllCharacteristics()));
        out.println("  Size of stack reserve:      " + getSizeOfStackReserve());
        out.println("  Size of stack commit:       " + getSizeOfStackCommit());
        out.println("  Size of heap reserve:       " + getSizeOfHeapReserve());
        out.println("  Size of heap commit:        " + getSizeOfHeapCommit());
        out.println("  Number of RVA and sizes:    " + getNumberOfRvaAndSizes());
        out.println();
        
        out.println("Data Directory");
        for (DataDirectoryType type : DataDirectoryType.values()) {
            DataDirectory entry = getDataDirectory(type);
            if (entry != null && entry.exists()) {
                out.printf("  %-30s 0x%08x %8d bytes\n", type, entry.getVirtualAddress(), entry.getSize());
            }
        }
        out.println();
        
        out.println("Sections");
        out.println("      Name     Virtual Size  Virtual Address  Raw Data Size  Raw Data Ptr  Characteristics");
        List<Section> sections = getSections();
        for (int i = 0; i < sections.size(); i++) {
            Section section = sections.get(i);
            out.printf("  #%d  %-8s     %8d       0x%08x       %8d    0x%08x  %s\n", i + 1, section.getName(), section.getVirtualSize(), section.getVirtualAddress(), section.getSizeOfRawData(), section.getPointerToRawData(), section.getCharacteristics());
        }
        out.println();
        
        List<CMSSignedData> signatures = getSignatures();
        if (!signatures.isEmpty()) {
            out.println("Signatures");
            for (CMSSignedData signedData : signatures) {
                SignerInformation signerInformation = signedData.getSignerInfos().getSigners().iterator().next();
                X509CertificateHolder certificate = (X509CertificateHolder) signedData.getCertificates().getMatches(signerInformation.getSID()).iterator().next();
                
                String commonName = certificate.getSubject().getRDNs(X509ObjectIdentifiers.commonName)[0].getFirst().getValue().toString();
                
                AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
                boolean timestamped = unsignedAttributes != null &&
                           (unsignedAttributes.get(PKCSObjectIdentifiers.pkcs_9_at_counterSignature) != null
                         || unsignedAttributes.get(AuthenticodeObjectIdentifiers.SPC_RFC3161_OBJID)  != null);
                DigestAlgorithm algorithm = DigestAlgorithm.of(signerInformation.getDigestAlgorithmID().getAlgorithm());
                out.println("  " + commonName + "  " + (algorithm != null ? "[" + algorithm.id + "]  " : "") + (timestamped ? "(timestamped)" : ""));
            }
        }
    }

    /**
     * Compute the digest of the file. The checksum field, the certificate
     * directory table entry and the certificate table are excluded from
     * the digest.
     */
    private synchronized byte[] computeDigest(MessageDigest digest) throws IOException {
        long checksumLocation = peHeaderOffset + 88;
        
        DataDirectory certificateTable = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        
        // digest from the beginning to the checksum field (excluded)
        updateDigest(digest, 0, checksumLocation);
        
        // skip the checksum field
        long position = checksumLocation + 4;
        
        // digest from the end of the checksum field to the beginning of the certificate table entry
        int certificateTableOffset = getDataDirectoryOffset() + 8 * DataDirectoryType.CERTIFICATE_TABLE.ordinal();
        updateDigest(digest, position, certificateTableOffset);
        
        // skip the certificate entry
        position = certificateTableOffset + 8;
        
        // todo digest the sections in ascending address order
        
        // digest from the end of the certificate table entry to the beginning of the certificate table
        if (certificateTable != null && certificateTable.exists()) {
            updateDigest(digest, position, certificateTable.getVirtualAddress());
            position = certificateTable.getVirtualAddress() + certificateTable.getSize();
        }
        
        // digest from the end of the certificate table to the end of the file
        updateDigest(digest, position, channel.size());
        
        return digest.digest();
    }

    /**
     * Update the specified digest by reading the underlying RandomAccessFile
     * from the start offset included to the end offset excluded.
     * 
     * @param digest
     * @param startOffset
     * @param endOffset
     */
    private void updateDigest(MessageDigest digest, long startOffset, long endOffset) throws IOException {
        channel.position(startOffset);
        
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        
        long position = startOffset;
        while (position < endOffset) {
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), endOffset - position));
            channel.read(buffer);
            buffer.rewind();
            
            digest.update(buffer);
            
            position += buffer.limit();
        }
    }

    /**
     * Compute the checksum of the file using the specified digest algorithm.
     * 
     * @param algorithm the digest algorithm, typically SHA1
     */
    public byte[] computeDigest(DigestAlgorithm algorithm) throws IOException {
        return computeDigest(algorithm.getMessageDigest());
    }

    /**
     * Increase the size of the file up to a size that is a multiple of the specified value.
     * 
     * @param multiple
     */
    public synchronized void pad(int multiple) throws IOException {
        long padding = (multiple - channel.size() % multiple) % multiple;
        channel.position(channel.size());
        channel.write(ByteBuffer.allocate((int) padding));
    }

    /**
     * A verification method for verifying signed signatures
     *
     * Apart from the authenticode_pe.docx microsoft provides https://www.ietf.org/rfc/rfc2315.txt was used to
     * implement this method
     */
    public void verify() throws VerificationException, IOException {

        MessageDigest md;
        List<CMSSignedData> signatures = getSignatures();

        if(!signatures.isEmpty()) {

            for(CMSSignedData signedData : signatures) {

                DigestAlgorithm signedDataAlgorithm = DigestAlgorithm.of(signedData.getDigestAlgorithmIDs().iterator().next().getAlgorithm());
                SignerInformation signerInformation;

                //get SpcIndirectContent structure from signed data, see pefile documentation
                ContentInfo contentInfo = signedData.toASN1Structure();
                SignedData signedData1 = SignedData.getInstance(contentInfo.getContent());
                ContentInfo contentInfo1 = signedData1.getEncapContentInfo();

                //Study ASN1Dump.dumpAsString() to implement getSpcIndirectDataContent(...) or any other ASN.1 parser
                DigestInfo digestInfo = getSpcIndirectDataContent(contentInfo1);
                DigestAlgorithm spcDigestAlgorithm = DigestAlgorithm.of((digestInfo.getAlgorithmId().getAlgorithm()));

                //#1 Check that the digest algorithms match
                if(signedData.getDigestAlgorithmIDs().size() != 1) {
                    throw new VerificationException("Signed Data must contain exactly one DigestAlgorithm");
                }

                //Check that SpcIndirectContent DigestAlgorithm equals CMSSignedData algorithm
                if(!(spcDigestAlgorithm.oid.getId()).equals(signedDataAlgorithm.oid.getId())) {
                    throw new VerificationException("Signed Data algorithm doesn't match with spcDigestAlgorithm");
                }

                //Check that SignerInfo DigestAlgorithm equals CMSSignedData algorithm
                if(signedData.getSignerInfos().size() != 1) {
                    throw new VerificationException("Signed Data must contain exactly one SignerInfo");
                }

                signerInformation = signedData.getSignerInfos().iterator().next();
                if(!(signerInformation.getDigestAlgorithmID().getAlgorithm().getId()).equals(signedDataAlgorithm.oid.getId())) {
                    throw new VerificationException("Signed Data algorithm doesn't match with SignerInformation algorithm");
                }

                //#2 Check the embedded hash in spcIndirectContent matches with the computed hash of the pefile
                if(!Arrays.equals(computeDigest(signedDataAlgorithm), digestInfo.getDigest()))
                    throw new VerificationException("The embedded hash in the SignedData is not equal to the computed hash");

                //#3 The hash of the spc blob should be equal to message digest in authenticated attributes of signed data
                //Get the message digest from authenticated attributes, see authenticode_pe documentation
                byte messageDigestInAuthenticatedAttr[];
                Attribute attribute = (Attribute)signerInformation.getSignedAttributes().toHashtable().get(CMSAttributes.messageDigest);
                Object digestObj = attribute.getAttrValues().iterator().next();

                if(digestObj instanceof ASN1OctetString) {

                    ASN1OctetString oct = (ASN1OctetString)digestObj;

                    messageDigestInAuthenticatedAttr = oct.getOctets();
                }
                else {
                    throw new VerificationException("No message digest was found in authenticated attributes");
                }

                //Get the spc blob
                byte[] spcBlob = getSpcBlob(contentInfo1.getContent().toASN1Primitive());

                //Now calculate the digest of the spcblob
                try {
                    md = MessageDigest.getInstance(signedData.getDigestAlgorithmIDs().iterator().next().getAlgorithm().toString());
                } catch (NoSuchAlgorithmException e) {
                    throw new VerificationException(e.getMessage());
                }

                md.update(spcBlob);
                byte[] spcDigest = md.digest();

                //Compare both and throw exception if not equal
                if(!Arrays.equals(messageDigestInAuthenticatedAttr, spcDigest))
                    throw new VerificationException("The hash of stripped content of SpcInfo does not match digest found in authenticated attributes");

                //#4 Check the hash in Authenticated Attributes with Encrypted Hash
                X509CertificateHolder h = (X509CertificateHolder) signedData.getCertificates().getMatches(signerInformation.getSID()).iterator().next();
                JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
                X509Certificate certificate = null;
                try {
                    certificate = converter.getCertificate(h);
                } catch (CertificateException e) {
                    throw new VerificationException(e.getMessage());
                }
                PublicKey key = certificate.getPublicKey();
                Signature signature = null;
                try {
                    SignerInfo signerInfo = signerInformation.toASN1Structure();
                    String digestAndEncryptionAlgorithmName = new DefaultCMSSignatureAlgorithmNameGenerator().getSignatureName(signerInformation.getDigestAlgorithmID(), signerInfo.getDigestEncryptionAlgorithm());
                    signature = Signature.getInstance(digestAndEncryptionAlgorithmName);
                } catch (NoSuchAlgorithmException e) {
                    throw new VerificationException(e.getMessage());
                }
                try {
                    signature.initVerify(key);
                } catch (InvalidKeyException e) {
                    throw new VerificationException(e.getMessage());
                }

                try {
                    signature.update(signerInformation.getEncodedSignedAttributes());
                    if(!signature.verify(signerInformation.getSignature())) {
                        throw new VerificationException("The hash in the the authenticated attributes doesn't match the encrypted hash(getSignature())");
                    }
                    //Note that the getSignature() method returns the encrypted hash in the SignerInformation
                } catch (SignatureException e) {
                    throw new VerificationException(e.getMessage());
                }

                //#4 Check the countersigner hash
                if(signerInformation.getCounterSignatures().size() != 0) {

                    SignerInformation counterSignerInformation = signerInformation.getCounterSignatures().iterator().next();
                    try {
                        md = MessageDigest.getInstance(counterSignerInformation.getDigestAlgorithmID().getAlgorithm().toString());
                    } catch (NoSuchAlgorithmException e) {
                        throw new VerificationException(e.getMessage());
                    }
                    md.update(signerInformation.getSignature());
                    byte[] authAttrHash = md.digest();

                    byte[] messageDigestInCounterSignature;
                    Attribute attributeOfCounterSignature = (Attribute)counterSignerInformation.getSignedAttributes().toHashtable().get(CMSAttributes.messageDigest);
                    Object digestObjOfCounterSignature = attributeOfCounterSignature.getAttrValues().iterator().next();

                    if(digestObjOfCounterSignature instanceof ASN1OctetString) {

                        ASN1OctetString oct = (ASN1OctetString)digestObjOfCounterSignature;

                        messageDigestInCounterSignature = oct.getOctets();
                    }
                    else {
                        throw new VerificationException("No message digest was found in authenticated attributes of counter signature");
                    }

                    //Compare both and throw exception if not equal
                    if(!Arrays.equals(messageDigestInCounterSignature, authAttrHash))
                        throw new VerificationException("The digest of encrypted hash in the signerInformation does not match with digest found in counter signature");

                }
            }
        }
        else {

            throw new VerificationException("No Signature Present");
        }
    }

    /**
     * This method returns the SpcIndirectDataContent data structure which is described in authenticode_pe.docx
     * This structure consists of the digest of the contents of the EXE which was calculated at the time of signing
     * This will be retrieved and compared to check if the digest calculated now matches with this digest
     * That's how we verify the integrity of the EXE
     *
     * @param contentInfo
     * @return
     */
    private DigestInfo getSpcIndirectDataContent(ContentInfo contentInfo) {

        DigestInfo digestInfo;

        AlgorithmIdentifier algId = null;
        byte[] digest = null;

        if((contentInfo.getContentType().getId()).equals(AuthenticodeObjectIdentifiers.SPC_INDIRECT_DATA_OBJID.getId())) {

            ASN1Primitive obj = contentInfo.getContent().toASN1Primitive();

            if(obj instanceof ASN1Sequence) {

                Enumeration e = ((ASN1Sequence)obj).getObjects();

                e.nextElement();
                Object messageDigestObj = e.nextElement();

                if(messageDigestObj instanceof ASN1Sequence) {

                    Enumeration e1 = ((ASN1Sequence)messageDigestObj).getObjects();


                    Object seq = e1.nextElement();
                    Object digestObj = e1.nextElement();

                    if(seq instanceof ASN1Sequence) {

                        Enumeration e2 = ((ASN1Sequence)seq).getObjects();

                        Object digestAlgorithmObj = e2.nextElement();

                        if(digestAlgorithmObj instanceof ASN1ObjectIdentifier) {

                            AlgorithmIdentifier a = new DefaultDigestAlgorithmIdentifierFinder().find(new DefaultAlgorithmNameFinder().getAlgorithmName((ASN1ObjectIdentifier) digestAlgorithmObj));
                            algId = AlgorithmIdentifier.getInstance(a);
                        }
                    }

                    if(digestObj instanceof ASN1OctetString) {

                        ASN1OctetString oct = (ASN1OctetString)digestObj;

                        digest = oct.getOctets();
                    }
                }
            }
        }

        digestInfo = new DigestInfo(algId, digest);

        return digestInfo;
    }

    /**
     * This method returns the constituents of the spcIndirectDataContent minus the some data
     * Refer RFC2315, 9.3 to find what have been omitted and the remaining is returned as bytes
     * This will be digested and compared to the digest in the AuthenticatedAttributes in the certificate
     *
     * @param primitive
     * @return
     * @throws IOException
     */
    private byte[] getSpcBlob(ASN1Primitive primitive) throws IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        if(primitive instanceof ASN1Sequence) {

            Iterator it = ((ASN1Sequence) primitive).iterator();

            while(it.hasNext()) {
                ASN1Primitive p = (ASN1Primitive)it.next();
                outputStream.write(p.getEncoded());
            }

            return outputStream.toByteArray();
        }

        return null;
    }
}

