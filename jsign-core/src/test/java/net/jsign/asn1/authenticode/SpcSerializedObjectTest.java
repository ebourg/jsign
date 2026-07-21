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

import static org.junit.Assert.*;

public class SpcSerializedObjectTest {

    @Test
    public void testSerializeAndDeserialize() throws Exception {
        SpcSerializedObject original = new SpcSerializedObject(new byte[] {0x01, 0x02, 0x03, 0x04});
        SpcSerializedObject decoded = SpcSerializedObject.parse(ASN1Sequence.getInstance(original.getEncoded()));

        assertArrayEquals("uuid", original.getClassId().getOctets(), decoded.getClassId().getOctets());
        assertArrayEquals("data", original.getSerializedData(), decoded.getSerializedData());
    }
}
