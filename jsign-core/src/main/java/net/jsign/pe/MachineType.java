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

/**
 * Target architecture of an executable file.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public enum MachineType {

    /** Executable assumed to be applicable to any machine type */
    UNKNOWN(0x0),

    /** Matsushita AM33 */
    AM33(0x1d3),

    /** x64 */
    AMD64(0x8664),

    /** ARM little endian */
    ARM(0x1c0),

    /** ARMv7 (or higher) Thumb mode only */
    ARMV7(0x1c4),

    /** ARMv8 in 64-bit mode */
    ARM64(0xaa64),

    /** EFI byte code */
    EBC(0xebc),

    /** Intel 386 or later processors and compatible processors */
    I386(0x14c),

    /** Intel Itanium processor family */
    IA64(0x200),

    /** Mitsubishi M32R little endian */
    M32R(0x9041),

    /** MIPS16 */
    MIPS16(0x266),

    /** MIPS with FPU */
    MIPSFPU(0x366),

    /** MIPS16 with FPU */
    MIPSFPU16(0x466),

    /** Power PC little endian */
    POWERPC(0x1f0),

    /** Power PC with floating point support */
    POWERPCFP(0x1f1),

    /** MIPS little endian */
    R4000(0x166),

    /** Hitachi SH3 */
    SH3(0x1a2),

    /** Hitachi SH3 DSP */
    SH3DSP(0x1a3),

    /** Hitachi SH4 */
    SH4(0x1a6),

    /** Hitachi SH5 */
    SH5(0x1a8),

    /** ARM or Thumb (interworking) */
    THUMB(0x1c2),

    /** MIPS little-endian WCE v2 */
    WCEMIPSV2(0x169); 

    private final int value;

    MachineType(int value) {
        this.value = value;
    }

    static MachineType valueOf(int value) {
        for (MachineType format : values()) {
            if (format.value == value) {
                return format;
            }
        }
        
        return null;
    }
}
