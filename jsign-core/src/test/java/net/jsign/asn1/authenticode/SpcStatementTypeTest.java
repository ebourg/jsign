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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Test;

import static org.junit.Assert.*;

public class SpcStatementTypeTest {

    @Test
    public void testSerializeAndDeserialize() throws Exception {
        SpcStatementType original = new SpcStatementType(AuthenticodeObjectIdentifiers.SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID);
        SpcStatementType decoded = SpcStatementType.parse(ASN1Sequence.getInstance(original.getEncoded()));

        assertEquals("identifier count", 1, decoded.getIdentifiers().size());
        assertEquals("identifier", AuthenticodeObjectIdentifiers.SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID, decoded.getIdentifiers().get(0));
    }

    @Test(expected=IllegalArgumentException.class)
    public void testInvalidIdentifier() {
        new SpcStatementType(new ASN1ObjectIdentifier("1.2.3.4.5"));
    }
}
