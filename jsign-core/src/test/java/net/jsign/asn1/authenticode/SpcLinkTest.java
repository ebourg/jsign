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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.Test;

import static org.junit.Assert.*;

public class SpcLinkTest {

    @Test
    public void testSerializeAndDeserializeUrl() throws Exception {
        SpcLink original = new SpcLink("https://example.com");
        SpcLink decoded = SpcLink.parse(ASN1TaggedObject.getInstance(original.toASN1Primitive().getEncoded()));

        assertEquals("url", original.getUrl(), decoded.getUrl());
    }

    @Test
    public void testDeserializeFile() {
        SpcLink decoded = SpcLink.parse(new DERTaggedObject(true, 2, new SpcString("My File")));

        assertEquals("file", "My File", decoded.getFile().getString());
    }
}
