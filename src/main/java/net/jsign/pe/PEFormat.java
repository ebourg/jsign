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

/**
 * Portable Executable Format.
 * 
 * @author Emmanuel Bourg
 * @since 1.0
 */
public enum PEFormat {
    
    PE32(0x10b, "PE32"),
    PE32plus(0x20b, "PE32+"),
    ROM(0x107, "ROM");

    final int value;
    final String label;

    PEFormat(int value, String label) {
        this.value = value;
        this.label = label;
    }
    
    static PEFormat valueOf(int value) {
        for (PEFormat format : values()) {
            if (format.value == value) {
                return format;
            }
        }
        
        return null;
    }
}
