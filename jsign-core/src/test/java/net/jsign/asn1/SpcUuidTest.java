/**
 * Copyright 2019 Emmanuel Bourg
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

package net.jsign.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.Test;

import net.jsign.asn1.authenticode.SpcUuid;

import static org.junit.Assert.*;

public class SpcUuidTest {

    @Test
    public void testUUID1() {
        SpcUuid uuid = new SpcUuid("F1100C00-0000-0000-C000-000000000046");
        ASN1OctetString asn1 = (DEROctetString) uuid.toASN1Primitive();
        assertArrayEquals(new byte[] {(byte) 0xF1, 0x10, 0x0C, 0x00,/*-*/0x00, 0x00,/*-*/0x00, 0x00,/*-*/(byte) 0xC0, 0x00,/*-*/0x00, 0x00, 0x00, 0x00, 0x00, 0x46}, asn1.getOctets());
    }

    @Test
    public void testUUID2() {
        SpcUuid uuid = new SpcUuid("1FCC3B60-594B-084E-B724-D2C6297EF351");
        ASN1OctetString asn1 = (DEROctetString) uuid.toASN1Primitive();
        assertArrayEquals(new byte[] {(byte) 0x1F, (byte) 0xCC, 0x3B, 0x60,/*-*/0x59, 0x4B,/*-*/0x08, 0x4E,/*-*/(byte) 0xB7, 0x24,/*-*/(byte) 0xD2, (byte) 0xC6, 0x29, 0x7E, (byte) 0xF3, 0x51}, asn1.getOctets());
    }
}
