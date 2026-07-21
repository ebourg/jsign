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

public class SpcSpOpusInfoTest {

    @Test
    public void testDecodeEncodedStructure() throws Exception {
        SpcSpOpusInfo original = new SpcSpOpusInfo("Jsign", "https://ebourg.github.io/jsign/");
        SpcSpOpusInfo decoded = SpcSpOpusInfo.parse(ASN1Sequence.getInstance(original.getEncoded()));

        assertEquals("program name", "Jsign", decoded.getProgramName());
        assertEquals("more info url", "https://ebourg.github.io/jsign/", decoded.getMoreInfo().getUrl());
    }
}
