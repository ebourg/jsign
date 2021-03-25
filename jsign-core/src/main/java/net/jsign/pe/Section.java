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

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Section of an executable file.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class Section {
    
    private final PEFile peFile;
    private final int baseOffset;

    Section(PEFile peFile, int baseOffset) {
        this.peFile = peFile;
        this.baseOffset = baseOffset;
    }

    /**
     * An 8-byte, null-padded UTF-8 encoded string. If the string is exactly
     * 8 characters long, there is no terminating null. For longer names, this
     * field contains a slash (/) that is followed by an ASCII representation
     * of a decimal number that is an offset into the string table. Executable
     * images do not use a string table and do not support section names longer
     * than 8 characters. Long names in object files are truncated if they are
     * emitted to an executable file.
     * 
     * @return the name of the section
     */
    public String getName() {
        byte[] buffer = new byte[8];
        peFile.read(buffer, baseOffset, 0);
        String name = new String(buffer, StandardCharsets.UTF_8);
        if (name.indexOf(0) != -1) {
            name = name.substring(0, name.indexOf(0));
        }
        
        return name;
    }

    /**
     * The total size of the section when loaded into memory. If this value is 
     * greater than SizeOfRawData, the section is zero-padded. This field is 
     * valid only for executable images and should be set to zero for object files.
     * 
     * @return the virtual size
     */
    public long getVirtualSize() {
        return peFile.readDWord(baseOffset, 8);
    }

    /**
     * For executable images, the address of the first byte of the section
     * relative to the image base when the section is loaded into memory.
     * For object files, this field is the address of the first byte before
     * relocation is applied; for simplicity, compilers should set this to zero.
     * Otherwise, it is an arbitrary value that is subtracted from offsets
     * during relocation.
     * 
     * @return the section address relative to the image base address
     */
    public long getVirtualAddress() {
        return peFile.readDWord(baseOffset, 12);
    }

    /**
     * The size of the section (for object files) or the size of the initialized
     * data on disk (for image files). For executable images, this must be a
     * multiple of FileAlignment from the optional header. If this is less than
     * VirtualSize, the remainder of the section is zero-filled. Because the
     * SizeOfRawData field is rounded but the VirtualSize field is not, it is
     * possible for SizeOfRawData to be greater than VirtualSize as well. When
     * a section contains only uninitialized data, this field should be zero.
     * 
     * @return the size of the section
     */
    public long getSizeOfRawData() {
        return peFile.readDWord(baseOffset, 16);
    }

    /**
     * The file pointer to the first page of the section within the COFF file.
     * For executable images, this must be a multiple of FileAlignment from the
     * optional header. For object files, the value should be aligned on a 4 byte
     * boundary for best performance. When a section contains only uninitialized
     * data, this field should be zero.
     * 
     * @return the file pointer to the first page
     */
    public long getPointerToRawData() {
        return peFile.readDWord(baseOffset, 20);
    }

    /**
     * The file pointer to the beginning of relocation entries for the section.
     * This is set to zero for executable images or if there are no relocations.
     * 
     * @return the file pointer to the beginning of relocation entries
     */
    public long getPointerToRelocations() {
        return peFile.readDWord(baseOffset, 24);
    }

    /**
     * The file pointer to the beginning of line-number entries for the section.
     * This is set to zero if there are no COFF line numbers. This value should 
     * be zero for an image because COFF debugging information is deprecated.
     * 
     * @return the file pointer to the beginning of line-number entries
     */
    public long getPointerToLineNumbers() {
        return peFile.readDWord(baseOffset, 28);
    }

    /**
     * The number of relocation entries for the section. This is set to zero
     * for executable images.
     * 
     * @return the number of relocation entries
     */
    public int getNumberOfRelocations() {
        return peFile.readWord(baseOffset, 32);
    }

    /**
     * The number of line-number entries for the section. This value should
     * be zero for an image because COFF debugging information is deprecated.
     * 
     * @return the number of line-number entries
     */
    public int getNumberOfLineNumbers() {
        return peFile.readWord(baseOffset, 34);
    }

    /**
     * The flags that describe the characteristics of the section.
     * 
     * @return the characteristics flags
     */
    public List<SectionFlag> getCharacteristics() {
        return SectionFlag.getFlags((int) peFile.readDWord(baseOffset, 36));
    }
}
