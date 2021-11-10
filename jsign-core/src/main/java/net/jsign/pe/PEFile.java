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
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
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
public class PEFile implements Signable, Closeable {

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
        this.file = file;
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
     * 
     * @return the number of sections
     */
    public int getNumberOfSections() {
        return readWord(peHeaderOffset, 6);
    }

    /**
     * The low 32 bits of the number of seconds since 00:00 January 1, 1970
     * (a C runtime time_t value), that indicates when the file was created.
     * 
     * @return the PE file creation date
     */
    public Date getTimeDateStamp() {
        return new Date(1000 * readDWord(peHeaderOffset, 8));
    }

    /**
     * The file offset of the COFF symbol table, or zero if no COFF symbol table
     * is present. This value should be zero for an image because COFF debugging
     * information is deprecated.
     * 
     * @return the offset of the COFF symbol table
     */
    public long getPointerToSymbolTable() {
        return readDWord(peHeaderOffset, 12);
    }

    /**
     * The number of entries in the symbol table. This data can be used to
     * locate the string table, which immediately follows the symbol table.
     * This value should be zero for an image because COFF debugging
     * information is deprecated.
     * 
     * @return the number of entries in the symbol table
     */
    public long getNumberOfSymbols() {
        return readDWord(peHeaderOffset, 16);
    }

    /**
     * The size of the optional header, which is required for executable files
     * but not for object files. This value should be zero for an object file.
     * 
     * @return the size of the optional header
     */
    public int getSizeOfOptionalHeader() {
        return readWord(peHeaderOffset, 20);
    }

    /**
     * The flags that indicate the attributes of the file. 
     * 
     * @return the characteristics flag
     */
    public int getCharacteristics() {
        return readWord(peHeaderOffset, 22);
    }
    
    public PEFormat getFormat() {
        return PEFormat.valueOf(readWord(peHeaderOffset, 24));
    }

    /**
     * The linker major version number.
     * 
     * @return the linker major version number
     */
    public int getMajorLinkerVersion() {
        return read(peHeaderOffset, 26);
    }

    /**
     * The linker minor version number.
     * 
     * @return the linker minor version number
     */
    public int getMinorLinkerVersion() {
        return read(peHeaderOffset, 27);
    }

    /**
     * The size of the code (text) section, or the sum of all code sections
     * if there are multiple sections.
     * 
     * @return the size of the code (text) section
     */
    public long getSizeOfCode() {
        return readDWord(peHeaderOffset, 28);
    }

    /**
     * The size of the initialized data section, or the sum of all such
     * sections if there are multiple data sections.
     * 
     * @return the size of the initialized data section
     */
    public long getSizeOfInitializedData() {
        return readDWord(peHeaderOffset, 32);
    }

    /**
     * The size of the uninitialized data section (BSS), or the sum of all such
     * sections if there are multiple BSS sections.
     * 
     * @return the size of the uninitialized data section (BSS)
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
     * 
     * @return the address of the entry point
     */
    public long getAddressOfEntryPoint() {
        return readDWord(peHeaderOffset, 40);
    }

    /**
     * The address that is relative to the image base of the beginning-of-code 
     * section when it is loaded into memory.
     * 
     * @return the code base address
     */
    public long getBaseOfCode() {
        return readDWord(peHeaderOffset, 44);
    }

    /**
     * The address that is relative to the image base of the beginning-of-data 
     * section when it is loaded into memory (PE32 only).
     * 
     * @return the data base address
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
     * 
     * @return the image base address
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
     * 
     * @return the size of the sections memory alignment (in bytes)
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
     * 
     * @return the alignment factor (in bytes)
     */
    public long getFileAlignment() {
        return readDWord(peHeaderOffset, 60);
    }

    /**
     * The major version number of the required operating system.
     * 
     * @return the major version number of the required operating system
     */
    public int getMajorOperatingSystemVersion() {
        return readWord(peHeaderOffset, 64);
    }

    /**
     * The minor version number of the required operating system.
     * 
     * @return the minor version number of the required operating system
     */
    public int getMinorOperatingSystemVersion() {
        return readWord(peHeaderOffset, 66);
    }

    /**
     * The major version number of the image.
     * 
     * @return the major version number of the image
     */
    public int getMajorImageVersion() {
        return readWord(peHeaderOffset, 68);
    }

    /**
     * The minor version number of the image.
     * 
     * @return the minor version number of the image
     */
    public int getMinorImageVersion() {
        return readWord(peHeaderOffset, 70);
    }

    /**
     * The major version number of the subsystem.
     * 
     * @return the major version number of the subsystem
     */
    public int getMajorSubsystemVersion() {
        return readWord(peHeaderOffset, 72);
    }

    /**
     * The minor version number of the subsystem.
     * 
     * @return the minor version number of the subsystem
     */
    public int getMinorSubsystemVersion() {
        return readWord(peHeaderOffset, 74);
    }

    /**
     * Reserved, must be zero.
     * 
     * @return zero
     */
    public long getWin32VersionValue() {
        return readDWord(peHeaderOffset, 76);
    }

    /**
     * The size (in bytes) of the image, including all headers, as the image
     * is loaded in memory. It must be a multiple of SectionAlignment.
     * 
     * @return the size of the image (in bytes)
     */
    public long getSizeOfImage() {
        return readDWord(peHeaderOffset, 80);
    }

    /**
     * The combined size of an MS DOS stub, PE header, and section headers
     * rounded up to a multiple of FileAlignment.
     * 
     * @return the combined size of the headers
     */
    public long getSizeOfHeaders() {
        return readDWord(peHeaderOffset, 84);
    }

    /**
     * The image file checksum.
     * 
     * @return the checksum of the image
     */
    public long getCheckSum() {
        return readDWord(peHeaderOffset, 88);
    }

    /**
     * Compute the checksum of the image file. The algorithm for computing
     * the checksum is incorporated into IMAGHELP.DLL.
     * 
     * @return the checksum of the image
     */
    public synchronized long computeChecksum() {
        PEImageChecksum checksum = new PEImageChecksum(peHeaderOffset + 88);
        
        ByteBuffer b = ByteBuffer.allocate(64 * 1024);
        
        try {
            channel.position(0);
            
            int len;
            while ((len = channel.read(b)) > 0) {
                b.flip();
                checksum.update(b.array(), 0, len);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        
        return checksum.getValue();
    }

    public synchronized void updateChecksum() {
        ByteBuffer buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt((int) computeChecksum());
        buffer.flip();

        try {
            channel.position(peHeaderOffset + 88);
            channel.write(buffer);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The subsystem that is required to run this image.
     * 
     * @return the required subsystem
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
     * 
     * @return the size of the stack to reserve
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
     * 
     * @return the size of the stack to commit
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
     * 
     * @return the size of the local heap space to reserve
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
     * 
     * @return the size of the local heap space to commit
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
     * 
     * @return zero
     */
    public long getLoaderFlags() {
        return readDWord(peHeaderOffset, PEFormat.PE32.equals(getFormat()) ? 112 : 128);
    }

    /**
     * The number of data-directory entries in the remainder of the optional
     * header. Each describes a location and size.
     * 
     * @return the number of data-directory entries
     */
    public int getNumberOfRvaAndSizes() {
        return (int) readDWord(peHeaderOffset, PEFormat.PE32.equals(getFormat()) ? 116 : 132);
    }

    int getDataDirectoryOffset() {
        return (int) peHeaderOffset + (PEFormat.PE32.equals(getFormat()) ? 120 : 136);
    }

    /**
     * Returns the data directory of the specified type.
     * 
     * @param type the type of data directory
     * @return the data directory of the specified type
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
     * @throws IOException if an I/O error occurs
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

    @Override
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

    @Override
    public void setSignature(CMSSignedData signature) throws IOException {
        CertificateTableEntry entry = new CertificateTableEntry(signature);
        writeDataDirectory(DataDirectoryType.CERTIFICATE_TABLE, entry.toBytes());
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
                out.printf("  %-30s 0x%08x %8d bytes%n", type, entry.getVirtualAddress(), entry.getSize());
            }
        }
        out.println();
        
        out.println("Sections");
        out.println("      Name     Virtual Size  Virtual Address  Raw Data Size  Raw Data Ptr  Characteristics");
        List<Section> sections = getSections();
        for (int i = 0; i < sections.size(); i++) {
            Section section = sections.get(i);
            out.printf("  #%d  %-8s     %8d       0x%08x       %8d    0x%08x  %s%n", i + 1, section.getName(), section.getVirtualSize(), section.getVirtualAddress(), section.getSizeOfRawData(), section.getPointerToRawData(), section.getCharacteristics());
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
     * 
     * @param digest the message digest to update
     * @return the digest of the file
     * @throws IOException if an I/O error occurs
     */
    @Override
    public synchronized byte[] computeDigest(MessageDigest digest) throws IOException {
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
        
        // todo digest the sections in ascending address order
        
        // digest from the end of the certificate table entry to the beginning of the certificate table
        if (certificateTable != null && certificateTable.exists()) {
            updateDigest(channel, digest, position, certificateTable.getVirtualAddress());
            position = certificateTable.getVirtualAddress() + certificateTable.getSize();
        }
        
        // digest from the end of the certificate table to the end of the file
        updateDigest(channel, digest, position, channel.size());
        
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
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(AuthenticodeObjectIdentifiers.SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());

        return new SpcIndirectDataContent(data, digestInfo);
    }

    /**
     * Increase the size of the file up to a size that is a multiple of the specified value.
     * 
     * @param multiple the size of the byte alignment
     * @throws IOException if an I/O error occurs
     */
    public synchronized void pad(int multiple) throws IOException {
        long padding = (multiple - channel.size() % multiple) % multiple;
        channel.position(channel.size());
        channel.write(ByteBuffer.allocate((int) padding));
    }
}
