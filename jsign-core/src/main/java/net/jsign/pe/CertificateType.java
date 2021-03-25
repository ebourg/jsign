/**
 * Copyright 2014 Emmanuel Bourg
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
 * Type of a WIN_CERTIFICATE structure.
 * 
 * @author Emmanuel Bourg
 * @since 1.3
 */
public enum CertificateType {

    /** X.509 Certificate (not supported) */
    X509(0x0001),

    /* PKCS#7 SignedData structure */
    PKCS_SIGNED_DATA(0x0002), 

    /** Reserved */
    RESERVED_1(0x0003),

    /** Terminal Server Protocol Stack Certificate (not supported) */
    TS_STACK_SIGNED(0x0004);

    private final short value;

    CertificateType(int value) {
        this.value = (short) value;
    }

    public short getValue() {
        return value;
    }
}
