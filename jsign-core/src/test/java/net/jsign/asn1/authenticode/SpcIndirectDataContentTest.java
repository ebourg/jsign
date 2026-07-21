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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.junit.Test;

import net.jsign.DigestAlgorithm;

import static net.jsign.asn1.authenticode.AuthenticodeObjectIdentifiers.*;
import static org.junit.Assert.*;

public class SpcIndirectDataContentTest {

    @Test
    public void testSerializeAndDeserialize() throws Exception {
        SpcSipInfo sipInfo = new SpcSipInfo(1, new SpcUuid("1FCC3B60-594B-084E-B724-D2C6297EF351"));
        SpcAttributeTypeAndOptionalValue data = new SpcAttributeTypeAndOptionalValue(SPC_SIPINFO_OBJID, sipInfo);
        DigestInfo digestInfo = new DigestInfo(new AlgorithmIdentifier(DigestAlgorithm.SHA256.oid), new byte[] {0x11, 0x22, 0x33, 0x44});

        SpcIndirectDataContent original = new SpcIndirectDataContent(data, digestInfo);
        SpcIndirectDataContent decoded = SpcIndirectDataContent.parse(ASN1Sequence.getInstance(original.getEncoded()));

        assertEquals("data type", data.getType(), decoded.getData().getType());
        assertEquals("sip version", 1, ((SpcSipInfo) decoded.getData().getValue()).getVersion());
        assertArrayEquals("sip uuid", sipInfo.getUUID().getOctets(), ((SpcSipInfo) decoded.getData().getValue()).getUUID().getOctets());
        assertEquals("digest algorithm", digestInfo.getAlgorithmId().getAlgorithm(), decoded.getMessageDigest().getAlgorithmId().getAlgorithm());
        assertArrayEquals("digest bytes", digestInfo.getDigest(), decoded.getMessageDigest().getDigest());
    }
}
