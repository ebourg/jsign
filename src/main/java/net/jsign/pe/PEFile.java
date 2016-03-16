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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import net.jsign.DigestAlgorithm;
import net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

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

    private final File file;
    private final ExtendedRandomAccessFile raf;

    public PEFile(File file) throws IOException {
        this.file = file;
        raf = new ExtendedRandomAccessFile(file, "rw");
        
        // DOS Header
        
        byte[] buffer = new byte[2];
        raf.read(buffer);
        
        if (!Arrays.equals(buffer, "MZ".getBytes())) {
            throw new IOException("DOS header signature not found");
        }
        
        raf.seek(0x3C);
        peHeaderOffset = raf.readDWord();
        
        // PE Header
        
        raf.seek(peHeaderOffset);
        
        buffer = new byte[4];
        raf.read(buffer);
        if (!Arrays.equals(buffer, new byte[] { 'P', 'E', 0, 0})) {
            throw new IOException("PE signature not found as expected at offset 0x" + Long.toHexString(peHeaderOffset));
        }
    }

    public synchronized void close() throws IOException {
        raf.close();
    }

    synchronized int read(byte[] buffer, long base, int offset) {
        try {
            raf.seek(base + offset);
            return raf.read(buffer);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    synchronized int read(long base, int offset) {
        try {
            raf.seek(base + offset);
            return raf.read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    synchronized int readWord(long base, int offset) {
        try {
            raf.seek(base + offset);
            return raf.readWord();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    synchronized long readDWord(long base, int offset) {
        try {
            raf.seek(base + offset);
            return raf.readDWord();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    synchronized long readQWord(long base, int offset) {
        try {
            raf.seek(base + offset);
            return raf.readQWord();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    synchronized void write(long base, byte[] data) {
        try {
            raf.seek(base);
            raf.write(data);
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
        
        byte[] b = new byte[64 * 1024];
        
        try {
            raf.seek(0);
            
            int len;
            while ((len = raf.read(b)) > 0) {
                checksum.update(b, 0, len);
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
            raf.seek(peHeaderOffset + 88);
            raf.write(buffer.array());
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
     * Writes the data directory of the specified type. The data is appended
     * at the end of the file. If a previous entry was already present it's
     * left as is in the file and is simply dereferenced from the table. 
     * 
     * @param type
     * @param data
     * @throws IOException
     */
    public synchronized void writeDataDirectory(DataDirectoryType type, byte[] data) throws IOException {
        // todo overwrite an existing entry at the end of the file
        
        // append the data directory at the end of the file
        long offset = raf.length();        
        
        raf.seek(offset);
        raf.write(data);
        
        // add the entry in the data directory table
        DataDirectory entry = getDataDirectory(type);
        entry.write(offset, data.length);
        
        updateChecksum();
    }

    /**
     * Returns the authenticode signatures on the file.
     */
    public synchronized List<CMSSignedData> getSignatures() {
        List<CMSSignedData> signatures = new ArrayList<CMSSignedData>();
        
        for (CertificateTableEntry entry : getCertificateTable()) {
            try {
                signatures.add(entry.getSignature());
            } catch (UnsupportedOperationException e) {
                // unsupported type, just skip
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        return signatures;
    }

    private synchronized List<CertificateTableEntry> getCertificateTable() {
        List<CertificateTableEntry> entries = new ArrayList<CertificateTableEntry>();
        DataDirectory certificateTable = getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        
        if (certificateTable != null && certificateTable.exists()) {
            long position = certificateTable.getVirtualAddress();
            
            try {
                entries.add(new CertificateTableEntry(this, position));
                
                // todo read the remaining signatures
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        
        return entries;
    }

    public synchronized List<Section> getSections() {
        List<Section> sections = new ArrayList<Section>();
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
        out.println("PE File");
        out.println("  Name:          " + file.getName());
        out.println("  Size:          " + file.length());
        out.println("  Last Modified: " + new Date(file.lastModified()));
        out.println();
        
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
        updateDigest(digest, position, raf.length());
        
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
        raf.seek(startOffset);
        
        byte[] buffer = new byte[8192];
        
        long position = startOffset;
        while (position < endOffset) {
            int length = (int) Math.min(buffer.length, endOffset - position);
            raf.read(buffer, 0, length);
            
            digest.update(buffer, 0, length);
            
            position += length;
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
        long padding = (multiple - raf.length() % multiple) % multiple;
        raf.seek(raf.length());
        for (int i = 0; i < padding; i++) {
            raf.writeByte(0);
        }
    }
}
