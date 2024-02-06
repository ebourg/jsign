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

package net.jsign.asn1.authenticode;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DigestInfo;

/**
 * <pre>
 * SpcIndirectDataContent ::= SEQUENCE {
 *     data                    SpcAttributeTypeAndOptionalValue,
 *     messageDigest           DigestInfo
 * }
 * </pre>
 *
 * @author Emmanuel Bourg
 * @since 1.0
 */
public class SpcIndirectDataContent extends DERSequence {

    public SpcIndirectDataContent(SpcAttributeTypeAndOptionalValue data, DigestInfo messageDigest) {
        super(new ASN1Encodable[] { data, messageDigest });
    }
}
