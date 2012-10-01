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
 * The subsystem of an executable file.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public enum Subsystem {

    /** An unknown subsystem */
    UNKNOWN(0),
    /** Device drivers and native Windows processes */
    NATIVE(1),
    /** The Windows graphical user interface (GUI) subsystem */
    WINDOWS_GUI(2),
    /** The Windows character subsystem */
    WINDOWS_CUI(3),
    /** The Posix character subsystem */
    POSIX_CUI(7),
    /** Windows CE */
    WINDOWS_CE_GUI(9),
    /** An Extensible Firmware Interface (EFI) application */
    EFI_APPLICATION(10),
    /** An EFI driver with boot services */
    EFI_BOOT_SERVICE_DRIVER(11),
    /** An EFI driver with run-time services */
    EFI_RUNTIME_DRIVER(12),
    /** An EFI ROM image */
    EFI_ROM(13),
    /** XBOX */
    XBOX(14);

    final int value;

    Subsystem(int value) {
        this.value = value;
    }

    static Subsystem valueOf(int value) {
        for (Subsystem format : values()) {
            if (format.value == value) {
                return format;
            }
        }

        return null;
    }
}
