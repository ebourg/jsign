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

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.Test;

import static org.junit.Assert.*;

public class SpcStringTest {

    @Test
    public void testSerializeAndDeserializeUnicode() throws Exception {
        SpcString original = new SpcString("Jsïgn");
        SpcString decoded = SpcString.parse(ASN1Primitive.fromByteArray(original.getEncoded()));

        assertEquals("Unicode string", original.getString(), decoded.getString());
    }

    @Test
    public void testDeserializeASCII() throws Exception {
        DERTaggedObject original = new DERTaggedObject(false, 1, new DERIA5String("Jsign"));
        SpcString decoded = SpcString.parse(ASN1Primitive.fromByteArray(original.getEncoded()));

        assertEquals("ASCII string", "Jsign", decoded.getString());
    }
}
