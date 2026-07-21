/*
 * Copyright 2026 Emmanuel Bourg
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

package net.jsign.asn1.authenticode;

import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Test;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;
import static org.junit.Assert.*;

public class SpcAttributeTypeAndOptionalValueTest {

    @Test
    public void testSerializeAndDeserializeSipInfo() throws Exception {
        SpcSipInfo sipInfo = new SpcSipInfo(1, new SpcUuid("1FCC3B60-594B-084E-B724-D2C6297EF351"));
        SpcAttributeTypeAndOptionalValue original = new SpcAttributeTypeAndOptionalValue(SPC_SIPINFO_OBJID, sipInfo);
        SpcAttributeTypeAndOptionalValue decoded = SpcAttributeTypeAndOptionalValue.parse(ASN1Sequence.getInstance(original.getEncoded()));

        assertEquals("type", original.getType(), decoded.getType());
        assertEquals("sip version", 1, ((SpcSipInfo) decoded.getValue()).getVersion());
        assertArrayEquals("sip uuid", sipInfo.getUUID().getOctets(), ((SpcSipInfo) decoded.getValue()).getUUID().getOctets());
    }

    @Test
    public void testSerializeAndDeserializePeImageData() throws Exception {
        SpcAttributeTypeAndOptionalValue original = new SpcAttributeTypeAndOptionalValue(SPC_PE_IMAGE_DATA_OBJID, new SpcPeImageData());
        SpcAttributeTypeAndOptionalValue decoded = SpcAttributeTypeAndOptionalValue.parse(ASN1Sequence.getInstance(original.getEncoded()));

        assertEquals("type", original.getType(), decoded.getType());
        assertNull("url", ((SpcPeImageData) decoded.getValue()).getFile().getUrl());
        assertEquals("file", "", ((SpcPeImageData) decoded.getValue()).getFile().getFile().getString());
    }
}
