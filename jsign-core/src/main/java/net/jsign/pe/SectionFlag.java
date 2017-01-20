/**
 * Copyright 2012 Emmanuel Bourg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http:/**www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.jsign.pe;

import java.util.ArrayList;
import java.util.List;

/**
 * Characteristics of the section of an executable file.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public enum SectionFlag {

    /** The section should not be padded to the next boundary. This flag is obsolete and is replaced by ALIGN_1BYTES. This is valid only for object files.. */
    TYPE_NO_PAD        (0x00000008),

    /** The section contains executable code. */
    CODE               (0x00000020),

    /** The section contains initialized data. */
    INITIALIZED_DATA   (0x00000040),

    /** The section contains uninitialized data. */
    UNINITIALIZED_DATA (0x00000080),

    /** Reserved for future use. */
    LNK_OTHER          (0x00000100),

    /** The section contains comments or other information. The .drectve section has this type. This is valid for object files only. */
    LNK_INFO           (0x00000200),

    /** The section will not become part of the image. This is valid only for object files. */
    LNK_REMOVE         (0x00000800),

    /** The section contains COMDAT data. This is valid only for object files. */
    LNK_COMDAT         (0x00001000),

    /** The section contains data referenced through the global pointer (GP). */
    GPREL              (0x00008000),

    /** Reserved for future use. */
    MEM_PURGEABLE      (0x00020000),

    /** For ARM machine types, the section contains Thumb code.  Reserved for future use with other machine types. */
    MEM_16BIT          (0x00020000),

    /** Reserved for future use. */
    MEM_LOCKED         (0x00040000),

    /** Reserved for future use. */
    MEM_PRELOAD        (0x00080000),

    /** Align data on a 1-byte boundary. Valid only for object files. */
    ALIGN_1BYTES       (0x00100000),

    /** Align data on a 2-byte boundary. Valid only for object files. */
    ALIGN_2BYTES       (0x00200000),

    /** Align data on a 4-byte boundary. Valid only for object files. */
    ALIGN_4BYTES       (0x00300000),

    /** Align data on an 8-byte boundary. Valid only for object files. */
    ALIGN_8BYTES       (0x00400000),

    /** Align data on a 16-byte boundary. Valid only for object files. */
    ALIGN_16BYTES      (0x00500000),

    /** Align data on a 32-byte boundary. Valid only for object files. */
    ALIGN_32BYTES      (0x00600000),

    /** Align data on a 64-byte boundary. Valid only for object files. */
    ALIGN_64BYTES      (0x00700000),

    /** Align data on a 128-byte boundary. Valid only for object files. */
    ALIGN_128BYTES     (0x00800000),

    /** Align data on a 256-byte boundary. Valid only for object files. */
    ALIGN_256BYTES     (0x00900000),

    /** Align data on a 512-byte boundary. Valid only for object files. */
    ALIGN_512BYTES     (0x00A00000),

    /** Align data on a 1024-byte boundary. Valid only for object files. */
    ALIGN_1024BYTES    (0x00B00000),

    /** Align data on a 2048-byte boundary. Valid only for object files. */
    ALIGN_2048BYTES    (0x00C00000),

    /** Align data on a 4096-byte boundary. Valid only for object files. */
    ALIGN_4096BYTES    (0x00D00000),

    /** Align data on an 8192-byte boundary. Valid only for object files. */
    ALIGN_8192BYTES    (0x00E00000),

    /** The section contains extended relocations. */
    LNK_NRELOC_OVFL    (0x01000000),

    /** The section can be discarded as needed. */
    MEM_DISCARDABLE    (0x02000000),

    /** The section cannot be cached. */
    MEM_NOT_CACHED     (0x04000000),

    /** The section is not pageable. */
    MEM_NOT_PAGED      (0x08000000),

    /** The section can be shared in memory. */
    MEM_SHARED         (0x10000000),

    /** The section can be executed as code. */
    EXECUTE            (0x20000000),

    /** The section can be read. */
    READ               (0x40000000),

    /** The section can be written to. */
    WRITE              (0x80000000);

    private final int mask;

    SectionFlag(int mask) {
        this.mask = mask;
    }

    static List<SectionFlag> getFlags(int flags) {
        List<SectionFlag> result = new ArrayList<>();
        
        for (SectionFlag flag : values()) {
            if ((flag.mask & flags) != 0) {
                result.add(flag);
            }
        }
        
        return result;
    }
}
